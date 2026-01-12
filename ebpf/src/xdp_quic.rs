//! XDP QUIC Protocol Filter
//!
//! XDP program for filtering QUIC (HTTP/3) traffic with:
//! - QUIC header validation
//! - Initial packet inspection
//! - Connection ID tracking
//! - Version validation
//! - Amplification attack prevention

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{HashMap, LruHashMap, PerCpuArray},
    programs::XdpContext,
};
use core::mem;

// ============================================================================
// Network Header Structures
// ============================================================================

#[repr(C)]
struct EthHdr {
    h_dest: [u8; 6],
    h_source: [u8; 6],
    h_proto: u16,
}

#[repr(C)]
struct Ipv4Hdr {
    version_ihl: u8,
    tos: u8,
    tot_len: u16,
    id: u16,
    frag_off: u16,
    ttl: u8,
    protocol: u8,
    check: u16,
    saddr: u32,
    daddr: u32,
}

#[repr(C)]
struct Ipv6Hdr {
    version_tc_flow: u32,
    payload_len: u16,
    nexthdr: u8,
    hop_limit: u8,
    saddr: [u8; 16],
    daddr: [u8; 16],
}

#[repr(C)]
struct UdpHdr {
    source: u16,
    dest: u16,
    len: u16,
    check: u16,
}

// ============================================================================
// QUIC Structures
// ============================================================================

/// QUIC Long Header (for Initial, Handshake, 0-RTT, Retry packets)
#[repr(C, packed)]
struct QuicLongHeader {
    /// Header form (1 bit) + Fixed bit (1 bit) + Long packet type (2 bits) + Type-specific bits (4 bits)
    header_byte: u8,
    /// QUIC version (4 bytes)
    version: u32,
    /// Destination Connection ID length (1 byte)
    dcid_len: u8,
}

/// QUIC connection state tracking
#[repr(C)]
pub struct QuicConnectionState {
    /// Connection state: 0=unknown, 1=initial, 2=handshake, 3=established, 4=closing
    pub state: u8,
    /// QUIC version being used
    pub version: u32,
    /// Packets received
    pub packets: u64,
    /// Bytes received
    pub bytes: u64,
    /// First seen timestamp
    pub first_seen: u64,
    /// Last seen timestamp
    pub last_seen: u64,
    /// Initial packets received (for amplification tracking)
    pub initial_packets: u32,
    /// Response data sent (for amplification tracking)
    pub response_bytes: u64,
    /// Flags
    pub flags: u32,
}

/// Per-IP QUIC rate limiting
#[repr(C)]
pub struct QuicRateLimit {
    /// Packets in current window
    pub packets: u64,
    /// Window start timestamp
    pub window_start: u64,
    /// Initial packets (special limiting for amplification)
    pub initial_packets: u64,
    /// Connection attempts
    pub connection_attempts: u32,
    /// Blocked until timestamp
    pub blocked_until: u64,
}

/// QUIC filter configuration
#[repr(C)]
#[derive(Copy, Clone)]
pub struct QuicConfig {
    /// Filter enabled
    pub enabled: u32,
    /// QUIC port (default 443)
    pub quic_port: u16,
    /// Alternative QUIC port (default 8443)
    pub alt_quic_port: u16,
    /// Maximum initial packets per connection (amplification limit)
    pub max_initial_packets: u32,
    /// Maximum unverified data (amplification factor limit, default 3x)
    pub max_amplification_factor: u32,
    /// Maximum connections per IP
    pub max_connections_per_ip: u32,
    /// Rate limit window (nanoseconds)
    pub rate_limit_window_ns: u64,
    /// Maximum packets per window
    pub max_packets_per_window: u64,
    /// Block duration (nanoseconds)
    pub block_duration_ns: u64,
    /// Protection level
    pub protection_level: u32,
}

/// QUIC statistics
#[repr(C)]
pub struct QuicStats {
    pub total_packets: u64,
    pub passed_packets: u64,
    pub dropped_invalid_header: u64,
    pub dropped_invalid_version: u64,
    pub dropped_amplification: u64,
    pub dropped_rate_limited: u64,
    pub dropped_blocked_ip: u64,
    pub initial_packets: u64,
    pub handshake_packets: u64,
    pub short_header_packets: u64,
}

// ============================================================================
// QUIC Constants
// ============================================================================

// QUIC header flags
const QUIC_HEADER_FORM_LONG: u8 = 0x80; // Long header
const QUIC_FIXED_BIT: u8 = 0x40; // Fixed bit (must be 1)
const QUIC_LONG_PACKET_TYPE_MASK: u8 = 0x30;

// QUIC long packet types (in bits 4-5)
const QUIC_PACKET_TYPE_INITIAL: u8 = 0x00;
const QUIC_PACKET_TYPE_0RTT: u8 = 0x10;
const QUIC_PACKET_TYPE_HANDSHAKE: u8 = 0x20;
const QUIC_PACKET_TYPE_RETRY: u8 = 0x30;

// QUIC versions (in network byte order)
const QUIC_VERSION_1: u32 = 0x00000001; // RFC 9000
const QUIC_VERSION_2: u32 = 0x6b3343cf; // RFC 9369
const QUIC_VERSION_NEGOTIATION: u32 = 0x00000000;

// Draft versions (commonly seen)
const QUIC_VERSION_DRAFT_29: u32 = 0xff00001d;
const QUIC_VERSION_DRAFT_32: u32 = 0xff000020;
const QUIC_VERSION_DRAFT_34: u32 = 0xff000022;

// Greased versions (random, should be ignored)
// Pattern: 0x?a?a?a?a where ? can be any hex digit

// Connection state flags
const FLAG_VERSION_VALIDATED: u32 = 0x0001;
const FLAG_ADDRESS_VALIDATED: u32 = 0x0002;
const FLAG_RETRY_SENT: u32 = 0x0004;
const FLAG_SUSPICIOUS: u32 = 0x0008;

// Limits
const MAX_DCID_LENGTH: u8 = 20;
const MAX_SCID_LENGTH: u8 = 20;
const MIN_INITIAL_PACKET_SIZE: usize = 1200; // RFC 9000 requirement
const MAX_AMPLIFICATION_FACTOR: u32 = 3; // RFC 9000: 3x amplification limit

// Default configuration
const DEFAULT_QUIC_PORT: u16 = 443;
const DEFAULT_ALT_QUIC_PORT: u16 = 8443;
const DEFAULT_MAX_INITIAL_PACKETS: u32 = 10;
const DEFAULT_MAX_CONNECTIONS_PER_IP: u32 = 100;
const DEFAULT_RATE_LIMIT_WINDOW_NS: u64 = 1_000_000_000; // 1 second
const DEFAULT_MAX_PACKETS_PER_WINDOW: u64 = 1000;
const DEFAULT_BLOCK_DURATION_NS: u64 = 60_000_000_000; // 60 seconds

// ============================================================================
// eBPF Maps
// ============================================================================

/// QUIC connection tracking (keyed by DCID hash + src_ip)
#[map]
static QUIC_CONNECTIONS: LruHashMap<u64, QuicConnectionState> =
    LruHashMap::with_max_entries(1_000_000, 0);

/// Per-IP rate limiting (IPv4)
#[map]
static QUIC_RATE_LIMITS_V4: LruHashMap<u32, QuicRateLimit> =
    LruHashMap::with_max_entries(500_000, 0);

/// Per-IP rate limiting (IPv6)
#[map]
static QUIC_RATE_LIMITS_V6: LruHashMap<[u8; 16], QuicRateLimit> =
    LruHashMap::with_max_entries(250_000, 0);

/// Known valid connection IDs (for short header validation)
#[map]
static QUIC_VALID_CIDS: LruHashMap<u64, u64> = LruHashMap::with_max_entries(500_000, 0);

/// Whitelisted IPs
#[map]
static QUIC_WHITELIST: HashMap<u32, u32> = HashMap::with_max_entries(10_000, 0);

/// Configuration
#[map]
static QUIC_CONFIG: PerCpuArray<QuicConfig> = PerCpuArray::with_max_entries(1, 0);

/// Statistics
#[map]
static QUIC_STATS: PerCpuArray<QuicStats> = PerCpuArray::with_max_entries(1, 0);

// ============================================================================
// Constants
// ============================================================================

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const IPPROTO_UDP: u8 = 17;

// ============================================================================
// Main XDP Entry Point
// ============================================================================

#[xdp]
pub fn xdp_quic(ctx: XdpContext) -> u32 {
    match try_xdp_quic(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn try_xdp_quic(ctx: XdpContext) -> Result<u32, ()> {
    let config = get_config();
    if config.enabled == 0 {
        return Ok(xdp_action::XDP_PASS);
    }

    let data = ctx.data();
    let data_end = ctx.data_end();

    // Parse Ethernet header
    if data + mem::size_of::<EthHdr>() > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let eth = unsafe { &*(data as *const EthHdr) };
    let eth_proto = u16::from_be(eth.h_proto);

    match eth_proto {
        ETH_P_IP => process_ipv4(&ctx, data + mem::size_of::<EthHdr>(), data_end, &config),
        ETH_P_IPV6 => process_ipv6(&ctx, data + mem::size_of::<EthHdr>(), data_end, &config),
        _ => Ok(xdp_action::XDP_PASS),
    }
}

// ============================================================================
// IPv4 Processing
// ============================================================================

#[inline(always)]
fn process_ipv4(
    ctx: &XdpContext,
    data: usize,
    data_end: usize,
    config: &QuicConfig,
) -> Result<u32, ()> {
    if data + mem::size_of::<Ipv4Hdr>() > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip = unsafe { &*(data as *const Ipv4Hdr) };

    // Only process UDP
    if ip.protocol != IPPROTO_UDP {
        return Ok(xdp_action::XDP_PASS);
    }

    let src_ip = u32::from_be(ip.saddr);

    // Check whitelist
    if unsafe { QUIC_WHITELIST.get(&src_ip) }.is_some() {
        return Ok(xdp_action::XDP_PASS);
    }

    // Check if IP is blocked
    if is_ip_blocked_v4(src_ip) {
        update_stats_blocked();
        return Ok(xdp_action::XDP_DROP);
    }

    let ihl = (ip.version_ihl & 0x0f) as usize * 4;
    let udp_data = data + ihl;

    process_udp_quic(ctx, udp_data, data_end, src_ip, config)
}

// ============================================================================
// IPv6 Processing
// ============================================================================

#[inline(always)]
fn process_ipv6(
    ctx: &XdpContext,
    data: usize,
    data_end: usize,
    config: &QuicConfig,
) -> Result<u32, ()> {
    if data + mem::size_of::<Ipv6Hdr>() > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip6 = unsafe { &*(data as *const Ipv6Hdr) };

    // Only process UDP
    if ip6.nexthdr != IPPROTO_UDP {
        return Ok(xdp_action::XDP_PASS);
    }

    let src_ip = ip6.saddr;

    // Check if IP is blocked
    if is_ip_blocked_v6(&src_ip) {
        update_stats_blocked();
        return Ok(xdp_action::XDP_DROP);
    }

    let udp_data = data + mem::size_of::<Ipv6Hdr>();

    // Use last 4 bytes of IPv6 as simplified key
    let ip_key = u32::from_be_bytes([src_ip[12], src_ip[13], src_ip[14], src_ip[15]]);

    process_udp_quic(ctx, udp_data, data_end, ip_key, config)
}

// ============================================================================
// UDP/QUIC Processing
// ============================================================================

#[inline(always)]
fn process_udp_quic(
    ctx: &XdpContext,
    data: usize,
    data_end: usize,
    src_ip: u32,
    config: &QuicConfig,
) -> Result<u32, ()> {
    if data + mem::size_of::<UdpHdr>() > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let udp = unsafe { &*(data as *const UdpHdr) };
    let dst_port = u16::from_be(udp.dest);
    let src_port = u16::from_be(udp.source);
    let udp_len = u16::from_be(udp.len) as usize;

    // Check if this is QUIC traffic (by port)
    let quic_port = if config.quic_port != 0 {
        config.quic_port
    } else {
        DEFAULT_QUIC_PORT
    };
    let alt_quic_port = if config.alt_quic_port != 0 {
        config.alt_quic_port
    } else {
        DEFAULT_ALT_QUIC_PORT
    };

    if dst_port != quic_port && dst_port != alt_quic_port {
        return Ok(xdp_action::XDP_PASS);
    }

    // Update total stats
    update_stats_total();

    // Check rate limit
    if !check_rate_limit_v4(src_ip, config) {
        update_stats_rate_limited();
        return Ok(xdp_action::XDP_DROP);
    }

    // Parse QUIC packet
    let quic_data = data + mem::size_of::<UdpHdr>();
    let quic_len = udp_len.saturating_sub(mem::size_of::<UdpHdr>());

    if quic_data >= data_end || quic_len < 1 {
        return Ok(xdp_action::XDP_PASS);
    }

    // Read first byte to determine header type
    let first_byte = unsafe { *(quic_data as *const u8) };

    // Check fixed bit (must be 1 for valid QUIC packets)
    if first_byte & QUIC_FIXED_BIT == 0 {
        // Fixed bit not set - could be version negotiation or invalid
        // Allow version negotiation (version = 0)
        if is_long_header(first_byte) {
            // Check if it's version negotiation
            if quic_data + 5 <= data_end {
                let version = unsafe { u32::from_be(*((quic_data + 1) as *const u32)) };
                if version == QUIC_VERSION_NEGOTIATION {
                    update_stats_passed();
                    return Ok(xdp_action::XDP_PASS);
                }
            }
        }
        update_stats_invalid_header();
        return Ok(xdp_action::XDP_DROP);
    }

    if is_long_header(first_byte) {
        // Long header packet
        process_quic_long_header(ctx, quic_data, data_end, src_ip, src_port, quic_len, config)
    } else {
        // Short header packet
        process_quic_short_header(ctx, quic_data, data_end, src_ip, src_port, quic_len, config)
    }
}

// ============================================================================
// QUIC Long Header Processing
// ============================================================================

#[inline(always)]
fn process_quic_long_header(
    ctx: &XdpContext,
    data: usize,
    data_end: usize,
    src_ip: u32,
    src_port: u16,
    quic_len: usize,
    config: &QuicConfig,
) -> Result<u32, ()> {
    // Need at least: header_byte (1) + version (4) + dcid_len (1) = 6 bytes
    if data + 6 > data_end {
        update_stats_invalid_header();
        return Ok(xdp_action::XDP_DROP);
    }

    let header_byte = unsafe { *(data as *const u8) };
    let version = unsafe { u32::from_be(*((data + 1) as *const u32)) };
    let dcid_len = unsafe { *((data + 5) as *const u8) };

    // Validate version
    if !is_valid_quic_version(version) {
        update_stats_invalid_version();
        if config.protection_level >= 2 {
            block_ip_v4(src_ip, config.block_duration_ns / 2);
        }
        return Ok(xdp_action::XDP_DROP);
    }

    // Validate DCID length
    if dcid_len > MAX_DCID_LENGTH {
        update_stats_invalid_header();
        return Ok(xdp_action::XDP_DROP);
    }

    // Check we have enough data for DCID
    let dcid_start = data + 6;
    if dcid_start + dcid_len as usize > data_end {
        update_stats_invalid_header();
        return Ok(xdp_action::XDP_DROP);
    }

    // Get SCID length
    let scid_len_offset = dcid_start + dcid_len as usize;
    if scid_len_offset >= data_end {
        update_stats_invalid_header();
        return Ok(xdp_action::XDP_DROP);
    }

    let scid_len = unsafe { *(scid_len_offset as *const u8) };
    if scid_len > MAX_SCID_LENGTH {
        update_stats_invalid_header();
        return Ok(xdp_action::XDP_DROP);
    }

    // Determine packet type
    let packet_type = header_byte & QUIC_LONG_PACKET_TYPE_MASK;

    let now = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };

    match packet_type {
        QUIC_PACKET_TYPE_INITIAL => {
            update_stats_initial();

            // RFC 9000: Initial packets must be at least 1200 bytes
            if quic_len < MIN_INITIAL_PACKET_SIZE {
                update_stats_invalid_header();
                return Ok(xdp_action::XDP_DROP);
            }

            // Amplification attack prevention
            // Track this connection and limit responses
            let conn_key = make_connection_key(src_ip, src_port, dcid_len, data, dcid_start);

            if let Some(conn) = unsafe { QUIC_CONNECTIONS.get_ptr_mut(&conn_key) } {
                let conn = unsafe { &mut *conn };
                conn.initial_packets += 1;
                conn.packets += 1;
                conn.bytes += quic_len as u64;
                conn.last_seen = now;

                // Check amplification limit
                let max_initial = if config.max_initial_packets != 0 {
                    config.max_initial_packets
                } else {
                    DEFAULT_MAX_INITIAL_PACKETS
                };

                if conn.initial_packets > max_initial {
                    update_stats_amplification();
                    return Ok(xdp_action::XDP_DROP);
                }
            } else {
                // New connection
                let conn = QuicConnectionState {
                    state: 1, // Initial
                    version,
                    packets: 1,
                    bytes: quic_len as u64,
                    first_seen: now,
                    last_seen: now,
                    initial_packets: 1,
                    response_bytes: 0,
                    flags: FLAG_VERSION_VALIDATED,
                };
                let _ = QUIC_CONNECTIONS.insert(&conn_key, &conn, 0);

                // Register CID for short header tracking
                let cid_hash = hash_connection_id(data, dcid_start, dcid_len);
                let _ = QUIC_VALID_CIDS.insert(&cid_hash, &now, 0);
            }

            update_stats_passed();
            Ok(xdp_action::XDP_PASS)
        }

        QUIC_PACKET_TYPE_HANDSHAKE => {
            update_stats_handshake();

            // Handshake packets should come from established initial connections
            let conn_key = make_connection_key(src_ip, src_port, dcid_len, data, dcid_start);

            if let Some(conn) = unsafe { QUIC_CONNECTIONS.get_ptr_mut(&conn_key) } {
                let conn = unsafe { &mut *conn };

                // Update state
                if conn.state == 1 {
                    conn.state = 2; // Handshake
                }
                conn.packets += 1;
                conn.bytes += quic_len as u64;
                conn.last_seen = now;

                update_stats_passed();
                Ok(xdp_action::XDP_PASS)
            } else {
                // Handshake without initial - suspicious
                if config.protection_level >= 3 {
                    update_stats_invalid_header();
                    return Ok(xdp_action::XDP_DROP);
                }
                update_stats_passed();
                Ok(xdp_action::XDP_PASS)
            }
        }

        QUIC_PACKET_TYPE_0RTT => {
            // 0-RTT packets - allow with basic validation
            update_stats_passed();
            Ok(xdp_action::XDP_PASS)
        }

        QUIC_PACKET_TYPE_RETRY => {
            // Retry packets - should be server to client only
            // If we see these incoming, it's suspicious
            if config.protection_level >= 2 {
                update_stats_invalid_header();
                return Ok(xdp_action::XDP_DROP);
            }
            update_stats_passed();
            Ok(xdp_action::XDP_PASS)
        }

        _ => {
            // Unknown packet type
            update_stats_invalid_header();
            Ok(xdp_action::XDP_DROP)
        }
    }
}

// ============================================================================
// QUIC Short Header Processing
// ============================================================================

#[inline(always)]
fn process_quic_short_header(
    ctx: &XdpContext,
    data: usize,
    data_end: usize,
    src_ip: u32,
    src_port: u16,
    quic_len: usize,
    config: &QuicConfig,
) -> Result<u32, ()> {
    update_stats_short_header();

    // Short header format:
    // - Header byte (1 byte): form=0, fixed=1, spin bit, reserved, key phase, packet number length
    // - Destination Connection ID (variable, typically 8 bytes)
    // - Packet Number (1-4 bytes, encrypted)
    // - Payload (encrypted)

    // We can only do basic validation since payload is encrypted
    // Check for minimum viable packet size
    if quic_len < 9 {
        // Too small for valid short header packet
        update_stats_invalid_header();
        return Ok(xdp_action::XDP_DROP);
    }

    // For established connections with short headers,
    // we rely on rate limiting as we can't inspect encrypted payload

    update_stats_passed();
    Ok(xdp_action::XDP_PASS)
}

// ============================================================================
// Helper Functions
// ============================================================================

#[inline(always)]
fn is_long_header(first_byte: u8) -> bool {
    first_byte & QUIC_HEADER_FORM_LONG != 0
}

#[inline(always)]
fn is_valid_quic_version(version: u32) -> bool {
    // Version negotiation (special case)
    if version == QUIC_VERSION_NEGOTIATION {
        return true;
    }

    // RFC 9000 (QUIC v1)
    if version == QUIC_VERSION_1 {
        return true;
    }

    // RFC 9369 (QUIC v2)
    if version == QUIC_VERSION_2 {
        return true;
    }

    // Common draft versions (for compatibility)
    if version == QUIC_VERSION_DRAFT_29
        || version == QUIC_VERSION_DRAFT_32
        || version == QUIC_VERSION_DRAFT_34
    {
        return true;
    }

    // Check for greased versions (0x?a?a?a?a pattern)
    // These should be ignored/accepted per spec
    let masked = version & 0x0f0f0f0f;
    if masked == 0x0a0a0a0a {
        return true;
    }

    // Allow other draft versions (0xff0000XX)
    if (version & 0xff000000) == 0xff000000 {
        return true;
    }

    false
}

#[inline(always)]
fn make_connection_key(
    src_ip: u32,
    src_port: u16,
    dcid_len: u8,
    _data: usize,
    dcid_start: usize,
) -> u64 {
    // Create a connection key from IP, port, and DCID hash
    let mut key: u64 = (src_ip as u64) << 32;
    key |= (src_port as u64) << 16;

    // Simple hash of first few DCID bytes if available
    if dcid_len > 0 {
        let dcid_byte = unsafe { *(dcid_start as *const u8) };
        key |= dcid_byte as u64;
    }

    key
}

#[inline(always)]
fn hash_connection_id(data: usize, dcid_start: usize, dcid_len: u8) -> u64 {
    // Simple hash of connection ID
    let mut hash: u64 = 0;
    let len = core::cmp::min(dcid_len as usize, 8);

    for i in 0..len {
        let byte = unsafe { *((dcid_start + i) as *const u8) };
        hash = hash.wrapping_mul(31).wrapping_add(byte as u64);
    }

    hash
}

// ============================================================================
// Rate Limiting
// ============================================================================

#[inline(always)]
fn check_rate_limit_v4(src_ip: u32, config: &QuicConfig) -> bool {
    let now = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
    let window = if config.rate_limit_window_ns != 0 {
        config.rate_limit_window_ns
    } else {
        DEFAULT_RATE_LIMIT_WINDOW_NS
    };
    let max_packets = if config.max_packets_per_window != 0 {
        config.max_packets_per_window
    } else {
        DEFAULT_MAX_PACKETS_PER_WINDOW
    };

    if let Some(rate) = unsafe { QUIC_RATE_LIMITS_V4.get_ptr_mut(&src_ip) } {
        let rate = unsafe { &mut *rate };

        // Check if blocked
        if rate.blocked_until > now {
            return false;
        }

        // Check if in new window
        if now.saturating_sub(rate.window_start) > window {
            rate.window_start = now;
            rate.packets = 1;
            rate.initial_packets = 0;
            return true;
        }

        rate.packets += 1;

        if rate.packets > max_packets {
            // Exceeded rate limit
            rate.blocked_until = now + config.block_duration_ns;
            return false;
        }

        true
    } else {
        let rate = QuicRateLimit {
            packets: 1,
            window_start: now,
            initial_packets: 0,
            connection_attempts: 1,
            blocked_until: 0,
        };
        let _ = QUIC_RATE_LIMITS_V4.insert(&src_ip, &rate, 0);
        true
    }
}

#[inline(always)]
fn is_ip_blocked_v4(src_ip: u32) -> bool {
    if let Some(rate) = unsafe { QUIC_RATE_LIMITS_V4.get(&src_ip) } {
        let now = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
        rate.blocked_until > now
    } else {
        false
    }
}

#[inline(always)]
fn is_ip_blocked_v6(src_ip: &[u8; 16]) -> bool {
    if let Some(rate) = unsafe { QUIC_RATE_LIMITS_V6.get(src_ip) } {
        let now = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
        rate.blocked_until > now
    } else {
        false
    }
}

#[inline(always)]
fn block_ip_v4(src_ip: u32, duration_ns: u64) {
    let now = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
    let block_until = now
        + if duration_ns != 0 {
            duration_ns
        } else {
            DEFAULT_BLOCK_DURATION_NS
        };

    if let Some(rate) = unsafe { QUIC_RATE_LIMITS_V4.get_ptr_mut(&src_ip) } {
        let rate = unsafe { &mut *rate };
        rate.blocked_until = block_until;
    } else {
        let rate = QuicRateLimit {
            packets: 0,
            window_start: now,
            initial_packets: 0,
            connection_attempts: 0,
            blocked_until: block_until,
        };
        let _ = QUIC_RATE_LIMITS_V4.insert(&src_ip, &rate, 0);
    }
}

// ============================================================================
// Configuration
// ============================================================================

#[inline(always)]
fn get_config() -> QuicConfig {
    if let Some(config) = unsafe { QUIC_CONFIG.get_ptr(0) } {
        unsafe { *config }
    } else {
        QuicConfig {
            enabled: 1,
            quic_port: DEFAULT_QUIC_PORT,
            alt_quic_port: DEFAULT_ALT_QUIC_PORT,
            max_initial_packets: DEFAULT_MAX_INITIAL_PACKETS,
            max_amplification_factor: MAX_AMPLIFICATION_FACTOR,
            max_connections_per_ip: DEFAULT_MAX_CONNECTIONS_PER_IP,
            rate_limit_window_ns: DEFAULT_RATE_LIMIT_WINDOW_NS,
            max_packets_per_window: DEFAULT_MAX_PACKETS_PER_WINDOW,
            block_duration_ns: DEFAULT_BLOCK_DURATION_NS,
            protection_level: 2,
        }
    }
}

// ============================================================================
// Statistics
// ============================================================================

#[inline(always)]
fn update_stats_total() {
    if let Some(stats) = unsafe { QUIC_STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).total_packets += 1;
        }
    }
}

#[inline(always)]
fn update_stats_passed() {
    if let Some(stats) = unsafe { QUIC_STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).passed_packets += 1;
        }
    }
}

#[inline(always)]
fn update_stats_invalid_header() {
    if let Some(stats) = unsafe { QUIC_STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).dropped_invalid_header += 1;
        }
    }
}

#[inline(always)]
fn update_stats_invalid_version() {
    if let Some(stats) = unsafe { QUIC_STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).dropped_invalid_version += 1;
        }
    }
}

#[inline(always)]
fn update_stats_amplification() {
    if let Some(stats) = unsafe { QUIC_STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).dropped_amplification += 1;
        }
    }
}

#[inline(always)]
fn update_stats_rate_limited() {
    if let Some(stats) = unsafe { QUIC_STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).dropped_rate_limited += 1;
        }
    }
}

#[inline(always)]
fn update_stats_blocked() {
    if let Some(stats) = unsafe { QUIC_STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).dropped_blocked_ip += 1;
        }
    }
}

#[inline(always)]
fn update_stats_initial() {
    if let Some(stats) = unsafe { QUIC_STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).initial_packets += 1;
        }
    }
}

#[inline(always)]
fn update_stats_handshake() {
    if let Some(stats) = unsafe { QUIC_STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).handshake_packets += 1;
        }
    }
}

#[inline(always)]
fn update_stats_short_header() {
    if let Some(stats) = unsafe { QUIC_STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).short_header_packets += 1;
        }
    }
}

// ============================================================================
// Panic Handler
// ============================================================================

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
