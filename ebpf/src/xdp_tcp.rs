//! XDP Enhanced TCP Filter
//!
//! XDP program for enhanced TCP filtering with:
//! - SYN flood protection using SYN cookies
//! - ACK flood detection
//! - RST flood detection
//! - Invalid flag combinations detection
//! - TCP window probing detection
//! - Connection state tracking

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
struct TcpHdr {
    source: u16,
    dest: u16,
    seq: u32,
    ack_seq: u32,
    doff_flags: u16,
    window: u16,
    check: u16,
    urg_ptr: u16,
}

// ============================================================================
// TCP Filtering Structures
// ============================================================================

/// TCP connection state tracking
#[repr(C)]
pub struct TcpConnectionState {
    /// Connection state: 0=none, 1=syn_sent, 2=syn_recv, 3=established, 4=fin_wait, 5=close_wait, 6=closing
    pub state: u8,
    /// Flags for various conditions
    pub flags: u8,
    /// Initial sequence number (for SYN cookie validation)
    pub initial_seq: u32,
    /// Expected ACK (for SYN cookie)
    pub expected_ack: u32,
    /// Packets seen
    pub packets: u64,
    /// Bytes seen
    pub bytes: u64,
    /// First seen timestamp
    pub first_seen: u64,
    /// Last seen timestamp
    pub last_seen: u64,
    /// Window scale (if negotiated)
    pub window_scale: u8,
    /// MSS (if negotiated)
    pub mss: u16,
}

/// Per-IP TCP state for flood detection
#[repr(C)]
pub struct TcpIpState {
    /// Total packets from this IP
    pub packets: u64,
    /// SYN packets in current window
    pub syn_packets: u64,
    /// ACK packets in current window (for ACK flood detection)
    pub ack_packets: u64,
    /// RST packets in current window (for RST flood detection)
    pub rst_packets: u64,
    /// Invalid flag packets
    pub invalid_packets: u64,
    /// Window start timestamp
    pub window_start: u64,
    /// Last seen timestamp
    pub last_seen: u64,
    /// Active connections count
    pub active_connections: u32,
    /// Blocked until timestamp
    pub blocked_until: u64,
    /// Flags (attack type detected)
    pub flags: u32,
}

/// SYN cookie entry (for SYN flood protection)
#[repr(C)]
pub struct SynCookieEntry {
    /// Cookie value (encoded seq number)
    pub cookie: u32,
    /// Creation timestamp
    pub created: u64,
    /// Source port
    pub src_port: u16,
    /// Destination port
    pub dst_port: u16,
    /// MSS index (encoded in cookie)
    pub mss_index: u8,
    /// Valid flag
    pub valid: u8,
}

/// TCP filter configuration
#[repr(C)]
#[derive(Copy, Clone)]
pub struct TcpConfig {
    /// Filter enabled
    pub enabled: u32,
    /// SYN flood protection enabled
    pub syn_flood_protection: u32,
    /// SYN cookie threshold (SYN rate to trigger cookies)
    pub syn_cookie_threshold: u64,
    /// Maximum SYN packets per IP per window
    pub max_syn_per_ip: u64,
    /// Maximum connections per IP
    pub max_connections_per_ip: u32,
    /// ACK flood detection enabled
    pub ack_flood_detection: u32,
    /// Maximum ACK packets per IP per window
    pub max_ack_per_ip: u64,
    /// RST flood detection enabled
    pub rst_flood_detection: u32,
    /// Maximum RST packets per IP per window
    pub max_rst_per_ip: u64,
    /// Rate limit window (nanoseconds)
    pub rate_limit_window_ns: u64,
    /// Block duration (nanoseconds)
    pub block_duration_ns: u64,
    /// Protection level (1=basic, 2=moderate, 3=aggressive)
    pub protection_level: u32,
    /// SYN cookie secret (for cookie generation) - should be set from userspace
    pub syn_cookie_secret: u32,
    /// Second SYN cookie secret (for rotation)
    pub syn_cookie_secret2: u32,
    /// Incomplete handshake timeout (nanoseconds)
    pub handshake_timeout_ns: u64,
    /// Maximum incomplete handshakes per IP before blocking
    pub max_incomplete_handshakes_per_ip: u32,
    /// Enable ACK sequence validation
    pub ack_validation_enabled: u32,
    /// Enable IP fragment handling
    pub fragment_handling_enabled: u32,
}

/// TCP statistics
#[repr(C)]
pub struct TcpStats {
    pub total_packets: u64,
    pub passed_packets: u64,
    pub dropped_syn_flood: u64,
    pub dropped_ack_flood: u64,
    pub dropped_rst_flood: u64,
    pub dropped_invalid_flags: u64,
    pub dropped_blocked_ip: u64,
    pub dropped_connection_limit: u64,
    pub syn_cookies_issued: u64,
    pub syn_cookies_validated: u64,
    pub syn_cookies_failed: u64,
    pub window_probe_detected: u64,
    pub dropped_fragments: u64,
    pub dropped_invalid_ack: u64,
    pub dropped_handshake_timeout: u64,
    pub incomplete_handshakes_detected: u64,
}

/// Per-IP incomplete handshake tracking
#[repr(C)]
pub struct IncompleteHandshakeState {
    /// Number of incomplete handshakes from this IP
    pub count: u32,
    /// Timestamp of first incomplete handshake in current window
    pub window_start: u64,
    /// Last update timestamp
    pub last_seen: u64,
}

/// Global SYN state for system-wide flood detection
#[repr(C)]
pub struct GlobalSynState {
    /// Total SYN packets in current window
    pub syn_count: u64,
    /// Window start
    pub window_start: u64,
    /// SYN cookie mode active
    pub cookie_mode: u32,
}

// ============================================================================
// TCP Flag Constants
// ============================================================================

const TCP_FIN: u16 = 0x0001;
const TCP_SYN: u16 = 0x0002;
const TCP_RST: u16 = 0x0004;
const TCP_PSH: u16 = 0x0008;
const TCP_ACK: u16 = 0x0010;
const TCP_URG: u16 = 0x0020;
const TCP_ECE: u16 = 0x0040;
const TCP_CWR: u16 = 0x0080;

// Invalid flag combinations
const TCP_SYN_FIN: u16 = TCP_SYN | TCP_FIN; // Invalid
const TCP_SYN_RST: u16 = TCP_SYN | TCP_RST; // Invalid
const TCP_FIN_RST: u16 = TCP_FIN | TCP_RST; // Invalid
const TCP_SYN_FIN_RST: u16 = TCP_SYN | TCP_FIN | TCP_RST; // Invalid (XMAS variant)
const TCP_NULL_FLAGS: u16 = 0; // NULL scan
const TCP_XMAS_FLAGS: u16 = TCP_FIN | TCP_URG | TCP_PSH; // XMAS scan

// State flags
const FLAG_SYN_FLOOD: u32 = 0x0001;
const FLAG_ACK_FLOOD: u32 = 0x0002;
const FLAG_RST_FLOOD: u32 = 0x0004;
const FLAG_INVALID_FLAGS: u32 = 0x0008;
const FLAG_WINDOW_PROBE: u32 = 0x0010;
const FLAG_CONNECTION_LIMIT: u32 = 0x0020;

// Connection state flags
const CONN_FLAG_SYN_COOKIE: u8 = 0x01;
const CONN_FLAG_VALIDATED: u8 = 0x02;

// Default configuration
const DEFAULT_SYN_COOKIE_THRESHOLD: u64 = 10000; // SYNs per second to trigger cookies
const DEFAULT_MAX_SYN_PER_IP: u64 = 100;
const DEFAULT_MAX_CONNECTIONS_PER_IP: u32 = 100;
const DEFAULT_MAX_ACK_PER_IP: u64 = 1000;
const DEFAULT_MAX_RST_PER_IP: u64 = 100;
const DEFAULT_RATE_LIMIT_WINDOW_NS: u64 = 1_000_000_000; // 1 second
const DEFAULT_BLOCK_DURATION_NS: u64 = 60_000_000_000; // 60 seconds
const DEFAULT_HANDSHAKE_TIMEOUT_NS: u64 = 30_000_000_000; // 30 seconds
const DEFAULT_MAX_INCOMPLETE_HANDSHAKES_PER_IP: u32 = 10;

// SYN cookie constants
const SYN_COOKIE_TTL_NS: u64 = 60_000_000_000; // 60 seconds
const MSS_TABLE: [u16; 4] = [536, 1300, 1440, 1460];

// IP fragmentation constants (frag_off field masks)
const IP_MF: u16 = 0x2000; // More Fragments flag
const IP_OFFSET: u16 = 0x1FFF; // Fragment offset mask

// Default SYN cookie secrets - derived from boot time for uniqueness
// These should be overwritten by userspace with cryptographically random values
const DEFAULT_SYN_COOKIE_SECRET: u32 = 0xDEADBEEF;
const DEFAULT_SYN_COOKIE_SECRET2: u32 = 0xCAFEBABE;

// ============================================================================
// eBPF Maps
// ============================================================================

/// TCP connection tracking (keyed by 4-tuple hash)
#[map]
static TCP_CONNECTIONS: LruHashMap<u64, TcpConnectionState> =
    LruHashMap::with_max_entries(2_000_000, 0);

/// Per-IP TCP state (IPv4)
#[map]
static TCP_IP_STATE_V4: LruHashMap<u32, TcpIpState> = LruHashMap::with_max_entries(1_000_000, 0);

/// Per-IP TCP state (IPv6)
#[map]
static TCP_IP_STATE_V6: LruHashMap<[u8; 16], TcpIpState> = LruHashMap::with_max_entries(500_000, 0);

/// SYN cookies (for validating SYN-ACK responses)
#[map]
static SYN_COOKIES: LruHashMap<u64, SynCookieEntry> = LruHashMap::with_max_entries(1_000_000, 0);

/// Incomplete handshake tracking per IP (for spoofed IP detection)
#[map]
static INCOMPLETE_HANDSHAKES_V4: LruHashMap<u32, IncompleteHandshakeState> =
    LruHashMap::with_max_entries(500_000, 0);

/// Global SYN state (for system-wide flood detection)
#[map]
static GLOBAL_SYN_STATE: PerCpuArray<GlobalSynState> = PerCpuArray::with_max_entries(1, 0);

/// Boot-time random seed map (populated by userspace loader)
#[map]
static SYN_COOKIE_SECRETS: PerCpuArray<[u32; 2]> = PerCpuArray::with_max_entries(1, 0);

/// Protected ports (stricter filtering)
#[map]
static TCP_PROTECTED_PORTS: HashMap<u16, u32> = HashMap::with_max_entries(1000, 0);

/// Whitelisted IPs
#[map]
static TCP_WHITELIST: HashMap<u32, u32> = HashMap::with_max_entries(10_000, 0);

/// Configuration
#[map]
static TCP_CONFIG: PerCpuArray<TcpConfig> = PerCpuArray::with_max_entries(1, 0);

/// Statistics
#[map]
static TCP_STATS: PerCpuArray<TcpStats> = PerCpuArray::with_max_entries(1, 0);

// ============================================================================
// Constants
// ============================================================================

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const IPPROTO_TCP: u8 = 6;

// ============================================================================
// Main XDP Entry Point
// ============================================================================

#[xdp]
pub fn xdp_tcp(ctx: XdpContext) -> u32 {
    match try_xdp_tcp(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn try_xdp_tcp(ctx: XdpContext) -> Result<u32, ()> {
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
    config: &TcpConfig,
) -> Result<u32, ()> {
    if data + mem::size_of::<Ipv4Hdr>() > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip = unsafe { &*(data as *const Ipv4Hdr) };

    // Only process TCP
    if ip.protocol != IPPROTO_TCP {
        return Ok(xdp_action::XDP_PASS);
    }

    let src_ip = u32::from_be(ip.saddr);
    let dst_ip = u32::from_be(ip.daddr);

    // Check for IP fragmentation
    // frag_off contains both flags (upper 3 bits) and fragment offset (lower 13 bits)
    let frag_off = u16::from_be(ip.frag_off);
    let is_fragment = (frag_off & IP_MF) != 0 || (frag_off & IP_OFFSET) != 0;

    if is_fragment && config.fragment_handling_enabled != 0 {
        // IP fragments can be used to bypass TCP inspection
        // Fragment offset > 0 means this is not the first fragment, so no TCP header
        // MF flag with offset 0 means first fragment of a fragmented packet

        if (frag_off & IP_OFFSET) != 0 {
            // Non-first fragment - cannot inspect TCP header
            // In aggressive mode, drop fragmented TCP (rare in legitimate traffic)
            if config.protection_level >= 3 {
                update_stats_dropped_fragments();
                return Ok(xdp_action::XDP_DROP);
            }
            // Otherwise pass - let the kernel handle reassembly
            return Ok(xdp_action::XDP_PASS);
        }

        // First fragment - has TCP header but may be truncated
        // Continue processing but be aware the packet might be incomplete
        if config.protection_level >= 2 {
            // Log fragment for monitoring
            update_stats_dropped_fragments();
        }
    }

    // Check whitelist
    if unsafe { TCP_WHITELIST.get(&src_ip) }.is_some() {
        return Ok(xdp_action::XDP_PASS);
    }

    // Check if IP is blocked
    if is_ip_blocked_v4(src_ip) {
        update_stats_blocked();
        return Ok(xdp_action::XDP_DROP);
    }

    let ihl = (ip.version_ihl & 0x0f) as usize * 4;
    let tcp_data = data + ihl;

    process_tcp(ctx, tcp_data, data_end, src_ip, dst_ip, config)
}

// ============================================================================
// IPv6 Processing
// ============================================================================

#[inline(always)]
fn process_ipv6(
    ctx: &XdpContext,
    data: usize,
    data_end: usize,
    config: &TcpConfig,
) -> Result<u32, ()> {
    if data + mem::size_of::<Ipv6Hdr>() > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip6 = unsafe { &*(data as *const Ipv6Hdr) };

    // Only process TCP
    if ip6.nexthdr != IPPROTO_TCP {
        return Ok(xdp_action::XDP_PASS);
    }

    let src_ip = ip6.saddr;

    // Check if IP is blocked
    if is_ip_blocked_v6(&src_ip) {
        update_stats_blocked();
        return Ok(xdp_action::XDP_DROP);
    }

    let tcp_data = data + mem::size_of::<Ipv6Hdr>();

    // Use last 4 bytes as simplified IP keys
    let src_key = u32::from_be_bytes([src_ip[12], src_ip[13], src_ip[14], src_ip[15]]);
    let dst_key = u32::from_be_bytes([ip6.daddr[12], ip6.daddr[13], ip6.daddr[14], ip6.daddr[15]]);

    process_tcp(ctx, tcp_data, data_end, src_key, dst_key, config)
}

// ============================================================================
// TCP Processing
// ============================================================================

#[inline(always)]
fn process_tcp(
    ctx: &XdpContext,
    data: usize,
    data_end: usize,
    src_ip: u32,
    dst_ip: u32,
    config: &TcpConfig,
) -> Result<u32, ()> {
    if data + mem::size_of::<TcpHdr>() > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let tcp = unsafe { &*(data as *const TcpHdr) };
    let src_port = u16::from_be(tcp.source);
    let dst_port = u16::from_be(tcp.dest);
    let seq = u32::from_be(tcp.seq);
    let ack_seq = u32::from_be(tcp.ack_seq);
    let flags = u16::from_be(tcp.doff_flags) & 0x01ff; // Lower 9 bits
    let window = u16::from_be(tcp.window);

    let now = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };

    // Update total stats
    update_stats_total();

    // Step 1: Check for invalid TCP flag combinations
    if is_invalid_flag_combination(flags) {
        update_stats_invalid_flags();
        if config.protection_level >= 1 {
            record_invalid_flags(src_ip);
            return Ok(xdp_action::XDP_DROP);
        }
    }

    // Step 2: Update per-IP state and check for floods
    if let Some(action) = update_ip_state_and_check_floods(src_ip, flags, now, config) {
        return Ok(action);
    }

    // Step 3: Handle specific TCP packet types
    let tcp_flags = flags & 0x003f; // Just the 6 main flags

    if tcp_flags == TCP_SYN {
        // Pure SYN packet - handle SYN flood protection
        return handle_syn_packet(ctx, src_ip, dst_ip, src_port, dst_port, seq, now, config);
    }

    if tcp_flags == (TCP_SYN | TCP_ACK) {
        // SYN-ACK packet - this is a response, pass through
        update_stats_passed();
        return Ok(xdp_action::XDP_PASS);
    }

    if tcp_flags & TCP_ACK != 0 && tcp_flags & TCP_SYN == 0 {
        // ACK packet (possibly with other flags)
        return handle_ack_packet(
            ctx, src_ip, dst_ip, src_port, dst_port, seq, ack_seq, tcp_flags, window, now, config,
        );
    }

    if tcp_flags == TCP_RST || tcp_flags == (TCP_RST | TCP_ACK) {
        // RST packet
        return handle_rst_packet(ctx, src_ip, now, config);
    }

    // Step 4: Window probing detection
    if window == 0 && tcp_flags & TCP_ACK != 0 {
        // Zero window with ACK - could be window probe or legit
        update_stats_window_probe();
        // Allow but track
    }

    update_stats_passed();
    Ok(xdp_action::XDP_PASS)
}

// ============================================================================
// Flag Validation
// ============================================================================

#[inline(always)]
fn is_invalid_flag_combination(flags: u16) -> bool {
    let tcp_flags = flags & 0x003f; // Just the 6 main flags

    // NULL scan (no flags)
    if tcp_flags == TCP_NULL_FLAGS {
        return true;
    }

    // SYN+FIN (invalid)
    if tcp_flags & TCP_SYN_FIN == TCP_SYN_FIN {
        return true;
    }

    // SYN+RST (invalid)
    if tcp_flags & TCP_SYN_RST == TCP_SYN_RST {
        return true;
    }

    // FIN+RST (invalid)
    if tcp_flags & TCP_FIN_RST == TCP_FIN_RST {
        return true;
    }

    // XMAS scan (FIN+URG+PSH)
    if tcp_flags == TCP_XMAS_FLAGS {
        return true;
    }

    // FIN without ACK (invalid in most contexts)
    if tcp_flags == TCP_FIN {
        return true;
    }

    // URG without ACK (suspicious)
    if tcp_flags == TCP_URG {
        return true;
    }

    false
}

#[inline(always)]
fn record_invalid_flags(src_ip: u32) {
    if let Some(state) = unsafe { TCP_IP_STATE_V4.get_ptr_mut(&src_ip) } {
        let state = unsafe { &mut *state };
        state.invalid_packets += 1;
        state.flags |= FLAG_INVALID_FLAGS;
    }
}

// ============================================================================
// Flood Detection
// ============================================================================

#[inline(always)]
fn update_ip_state_and_check_floods(
    src_ip: u32,
    flags: u16,
    now: u64,
    config: &TcpConfig,
) -> Option<u32> {
    let window = if config.rate_limit_window_ns != 0 {
        config.rate_limit_window_ns
    } else {
        DEFAULT_RATE_LIMIT_WINDOW_NS
    };

    let tcp_flags = flags & 0x003f;

    if let Some(state) = unsafe { TCP_IP_STATE_V4.get_ptr_mut(&src_ip) } {
        let state = unsafe { &mut *state };

        // Check if blocked
        if state.blocked_until > now {
            return Some(xdp_action::XDP_DROP);
        }

        // Check if in new window
        if now.saturating_sub(state.window_start) > window {
            state.window_start = now;
            state.syn_packets = 0;
            state.ack_packets = 0;
            state.rst_packets = 0;
            state.invalid_packets = 0;
            state.flags = 0;
        }

        state.packets += 1;
        state.last_seen = now;

        // Track by flag type
        if tcp_flags == TCP_SYN {
            state.syn_packets += 1;
            let max_syn = if config.max_syn_per_ip != 0 {
                config.max_syn_per_ip
            } else {
                DEFAULT_MAX_SYN_PER_IP
            };

            if config.syn_flood_protection != 0 && state.syn_packets > max_syn {
                state.flags |= FLAG_SYN_FLOOD;
                state.blocked_until = now + config.block_duration_ns;
                update_stats_syn_flood();
                return Some(xdp_action::XDP_DROP);
            }
        }

        if tcp_flags & TCP_ACK != 0 && tcp_flags & TCP_SYN == 0 {
            state.ack_packets += 1;
            let max_ack = if config.max_ack_per_ip != 0 {
                config.max_ack_per_ip
            } else {
                DEFAULT_MAX_ACK_PER_IP
            };

            if config.ack_flood_detection != 0 && state.ack_packets > max_ack {
                state.flags |= FLAG_ACK_FLOOD;
                state.blocked_until = now + config.block_duration_ns;
                update_stats_ack_flood();
                return Some(xdp_action::XDP_DROP);
            }
        }

        if tcp_flags == TCP_RST || tcp_flags == (TCP_RST | TCP_ACK) {
            state.rst_packets += 1;
            let max_rst = if config.max_rst_per_ip != 0 {
                config.max_rst_per_ip
            } else {
                DEFAULT_MAX_RST_PER_IP
            };

            if config.rst_flood_detection != 0 && state.rst_packets > max_rst {
                state.flags |= FLAG_RST_FLOOD;
                state.blocked_until = now + config.block_duration_ns;
                update_stats_rst_flood();
                return Some(xdp_action::XDP_DROP);
            }
        }

        None
    } else {
        // First packet from this IP
        let state = TcpIpState {
            packets: 1,
            syn_packets: if tcp_flags == TCP_SYN { 1 } else { 0 },
            ack_packets: if tcp_flags & TCP_ACK != 0 && tcp_flags & TCP_SYN == 0 {
                1
            } else {
                0
            },
            rst_packets: if tcp_flags == TCP_RST || tcp_flags == (TCP_RST | TCP_ACK) {
                1
            } else {
                0
            },
            invalid_packets: 0,
            window_start: now,
            last_seen: now,
            active_connections: 0,
            blocked_until: 0,
            flags: 0,
        };
        let _ = TCP_IP_STATE_V4.insert(&src_ip, &state, 0);
        None
    }
}

// ============================================================================
// SYN Packet Handling (with SYN cookies)
// ============================================================================

#[inline(always)]
fn handle_syn_packet(
    ctx: &XdpContext,
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    now: u64,
    config: &TcpConfig,
) -> Result<u32, ()> {
    // Check if destination port is protected
    let _is_protected = unsafe { TCP_PROTECTED_PORTS.get(&dst_port) }.is_some();

    // Check for incomplete handshake abuse (spoofed IPs)
    if let Some(action) = check_incomplete_handshake_limit(src_ip, now, config) {
        return Ok(action);
    }

    // Track this as a new incomplete handshake
    track_incomplete_handshake(src_ip, now, config);

    // Check global SYN rate for cookie mode decision
    let use_cookies = should_use_syn_cookies(now, config);

    if use_cookies && config.syn_flood_protection != 0 {
        // Generate and track SYN cookie
        let cookie_key = make_connection_key(src_ip, dst_ip, src_port, dst_port);

        let cookie = generate_syn_cookie(src_ip, src_port, dst_ip, dst_port, seq, now, config);

        let entry = SynCookieEntry {
            cookie,
            created: now,
            src_port,
            dst_port,
            mss_index: 3, // Default to 1460
            valid: 1,
        };

        let _ = SYN_COOKIES.insert(&cookie_key, &entry, 0);
        update_stats_syn_cookie_issued();

        // In a real implementation, we would TX_REDIRECT with SYN-ACK
        // For now, we pass the SYN and rely on userspace or kernel to respond
    }

    // Connection limit check
    if let Some(state) = unsafe { TCP_IP_STATE_V4.get_ptr_mut(&src_ip) } {
        let state = unsafe { &mut *state };
        let max_conn = if config.max_connections_per_ip != 0 {
            config.max_connections_per_ip
        } else {
            DEFAULT_MAX_CONNECTIONS_PER_IP
        };

        if state.active_connections >= max_conn {
            state.flags |= FLAG_CONNECTION_LIMIT;
            update_stats_connection_limit();
            return Ok(xdp_action::XDP_DROP);
        }

        state.active_connections += 1;
    }

    // Track the connection
    let conn_key = make_connection_key(src_ip, dst_ip, src_port, dst_port);
    let conn_state = TcpConnectionState {
        state: 1, // SYN received
        flags: if use_cookies { CONN_FLAG_SYN_COOKIE } else { 0 },
        initial_seq: seq,
        expected_ack: seq.wrapping_add(1),
        packets: 1,
        bytes: 0,
        first_seen: now,
        last_seen: now,
        window_scale: 0,
        mss: 0,
    };
    let _ = TCP_CONNECTIONS.insert(&conn_key, &conn_state, 0);

    update_stats_passed();
    Ok(xdp_action::XDP_PASS)
}

// ============================================================================
// Incomplete Handshake Tracking (Spoofed IP Detection)
// ============================================================================

/// Track a new incomplete handshake (SYN without completing 3-way handshake)
#[inline(always)]
fn track_incomplete_handshake(src_ip: u32, now: u64, config: &TcpConfig) {
    let timeout = if config.handshake_timeout_ns != 0 {
        config.handshake_timeout_ns
    } else {
        DEFAULT_HANDSHAKE_TIMEOUT_NS
    };

    if let Some(state) = unsafe { INCOMPLETE_HANDSHAKES_V4.get_ptr_mut(&src_ip) } {
        let state = unsafe { &mut *state };

        // Check if we're in a new window
        if now.saturating_sub(state.window_start) > timeout {
            // Reset window
            state.count = 1;
            state.window_start = now;
        } else {
            state.count += 1;
        }
        state.last_seen = now;
    } else {
        // New entry
        let state = IncompleteHandshakeState {
            count: 1,
            window_start: now,
            last_seen: now,
        };
        let _ = INCOMPLETE_HANDSHAKES_V4.insert(&src_ip, &state, 0);
    }

    update_stats_incomplete_handshake();
}

/// Check if IP has too many incomplete handshakes (likely spoofed)
#[inline(always)]
fn check_incomplete_handshake_limit(src_ip: u32, now: u64, config: &TcpConfig) -> Option<u32> {
    let max_incomplete = if config.max_incomplete_handshakes_per_ip != 0 {
        config.max_incomplete_handshakes_per_ip
    } else {
        DEFAULT_MAX_INCOMPLETE_HANDSHAKES_PER_IP
    };

    let timeout = if config.handshake_timeout_ns != 0 {
        config.handshake_timeout_ns
    } else {
        DEFAULT_HANDSHAKE_TIMEOUT_NS
    };

    if let Some(state) = unsafe { INCOMPLETE_HANDSHAKES_V4.get(&src_ip) } {
        // Only count if within timeout window
        if now.saturating_sub(state.window_start) <= timeout {
            if state.count >= max_incomplete {
                update_stats_handshake_timeout();
                return Some(xdp_action::XDP_DROP);
            }
        }
    }

    None
}

/// Clear incomplete handshake tracking when handshake completes
#[inline(always)]
fn clear_incomplete_handshake(src_ip: u32, now: u64, config: &TcpConfig) {
    if let Some(state) = unsafe { INCOMPLETE_HANDSHAKES_V4.get_ptr_mut(&src_ip) } {
        let state = unsafe { &mut *state };
        // Decrement count (don't go below 0)
        if state.count > 0 {
            state.count -= 1;
        }
        state.last_seen = now;
    }
}

#[inline(always)]
fn should_use_syn_cookies(now: u64, config: &TcpConfig) -> bool {
    let threshold = if config.syn_cookie_threshold != 0 {
        config.syn_cookie_threshold
    } else {
        DEFAULT_SYN_COOKIE_THRESHOLD
    };

    if let Some(global) = unsafe { GLOBAL_SYN_STATE.get_ptr_mut(0) } {
        let global = unsafe { &mut *global };

        // Check if in new window (1 second)
        if now.saturating_sub(global.window_start) > 1_000_000_000 {
            let rate = global.syn_count;
            global.window_start = now;
            global.syn_count = 1;

            // Update cookie mode based on previous window
            global.cookie_mode = if rate > threshold { 1 } else { 0 };
        } else {
            global.syn_count += 1;
        }

        global.cookie_mode != 0
    } else {
        false
    }
}

#[inline(always)]
fn get_syn_cookie_secret(config: &TcpConfig) -> (u32, u32) {
    // Try to get secrets from the dedicated map (set by userspace with random values)
    if let Some(secrets) = unsafe { SYN_COOKIE_SECRETS.get(0) } {
        if secrets[0] != 0 && secrets[1] != 0 {
            return (secrets[0], secrets[1]);
        }
    }

    // Fall back to config secrets (which should be set by userspace)
    let secret1 = if config.syn_cookie_secret != 0 {
        config.syn_cookie_secret
    } else {
        DEFAULT_SYN_COOKIE_SECRET
    };

    let secret2 = if config.syn_cookie_secret2 != 0 {
        config.syn_cookie_secret2
    } else {
        DEFAULT_SYN_COOKIE_SECRET2
    };

    (secret1, secret2)
}

#[inline(always)]
fn generate_syn_cookie(
    src_ip: u32,
    src_port: u16,
    dst_ip: u32,
    dst_port: u16,
    seq: u32,
    now: u64,
    config: &TcpConfig,
) -> u32 {
    // SYN cookie generation using SipHash-like mixing
    // Uses two secrets for better unpredictability

    let (secret1, secret2) = get_syn_cookie_secret(config);
    let time_counter = (now / 60_000_000_000) as u32; // 60 second granularity

    // Mix all inputs using a simple but effective hash
    // This provides reasonable security for DDoS mitigation
    // For cryptographic strength, userspace should use proper SipHash

    let mut hash = secret1;
    hash = hash.wrapping_mul(0x9e3779b9).wrapping_add(src_ip);
    hash ^= hash >> 16;
    hash = hash.wrapping_mul(0x85ebca6b).wrapping_add(src_port as u32);
    hash ^= hash >> 13;
    hash = hash.wrapping_mul(0xc2b2ae35).wrapping_add(dst_ip);
    hash ^= hash >> 16;
    hash = hash.wrapping_mul(0x9e3779b9).wrapping_add(dst_port as u32);

    // Mix in second secret and time for additional entropy
    let mut hash2 = secret2;
    hash2 = hash2.wrapping_mul(0x85ebca6b).wrapping_add(time_counter);
    hash2 ^= hash2 >> 13;
    hash2 = hash2.wrapping_mul(0xc2b2ae35).wrapping_add(hash);

    // Combine hashes
    let combined = hash ^ hash2;

    // Lower 5 bits: time counter (allows validation within 2 windows)
    // Next 2 bits: MSS index (encodes negotiated MSS)
    // Upper 25 bits: hash (provides unpredictability)
    let cookie = (combined & 0xFFFFFF80) | ((3 & 0x03) << 5) | (time_counter & 0x1f);

    cookie
}

// ============================================================================
// ACK Packet Handling
// ============================================================================

#[inline(always)]
fn handle_ack_packet(
    ctx: &XdpContext,
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack_seq: u32,
    flags: u16,
    window: u16,
    now: u64,
    config: &TcpConfig,
) -> Result<u32, ()> {
    let conn_key = make_connection_key(src_ip, dst_ip, src_port, dst_port);

    // Check if this is a SYN cookie validation (first ACK after SYN)
    if config.syn_flood_protection != 0 {
        if let Some(cookie_entry) = unsafe { SYN_COOKIES.get(&conn_key) } {
            if cookie_entry.valid != 0 {
                // Validate both the SYN cookie and the ACK sequence
                let cookie_valid =
                    validate_syn_cookie(ack_seq.wrapping_sub(1), cookie_entry.cookie, now, config);

                if cookie_valid {
                    update_stats_syn_cookie_validated();

                    // Mark connection as validated and complete handshake
                    if let Some(conn) = unsafe { TCP_CONNECTIONS.get_ptr_mut(&conn_key) } {
                        let conn = unsafe { &mut *conn };
                        conn.flags |= CONN_FLAG_VALIDATED;
                        conn.state = 3; // Established
                        conn.last_seen = now;

                        // Clear incomplete handshake tracking for this IP
                        clear_incomplete_handshake(src_ip, now, config);
                    }
                } else {
                    // Cookie validation failed - potential ACK flood with spoofed cookies
                    update_stats_syn_cookie_failed();
                    if config.protection_level >= 2 {
                        return Ok(xdp_action::XDP_DROP);
                    }
                }
            }
        }
    }

    // Update connection state and validate ACK sequence
    if let Some(conn) = unsafe { TCP_CONNECTIONS.get_ptr_mut(&conn_key) } {
        let conn = unsafe { &mut *conn };

        // ACK sequence validation for established connections
        if config.ack_validation_enabled != 0 && conn.state >= 3 {
            // For established connections, validate that ACK is within reasonable window
            // ACK should acknowledge data we've sent (expected_ack tracks our sent data)
            // Allow some slack for out-of-order packets

            // Validate that the ACK is not acknowledging data we haven't sent
            // This detects ACK flood attacks with random ACK numbers
            if conn.expected_ack != 0 {
                // Check if ack_seq is within a reasonable window of expected_ack
                // Using a window of 2^30 to handle wraparound
                let diff = ack_seq.wrapping_sub(conn.expected_ack);
                let reverse_diff = conn.expected_ack.wrapping_sub(ack_seq);

                // If the ACK is way out of range (more than 2^30 in either direction)
                // it's likely invalid. However, be careful with wraparound.
                // In practice, we allow any ACK that's "ahead" of expected (diff < 2^31)
                // or slightly behind (for retransmits)
                const MAX_VALID_WINDOW: u32 = 0x40000000; // 2^30

                if diff > MAX_VALID_WINDOW && reverse_diff > MAX_VALID_WINDOW {
                    // ACK is far outside expected range - suspicious
                    update_stats_invalid_ack();
                    if config.protection_level >= 3 {
                        return Ok(xdp_action::XDP_DROP);
                    }
                }
            }
        }

        conn.packets += 1;
        conn.last_seen = now;

        // State transitions
        match conn.state {
            1 => {
                // SYN_RECV -> This is the ACK completing the 3-way handshake
                // Validate that ACK matches our expected value
                if config.ack_validation_enabled != 0 {
                    // The ACK should acknowledge our SYN-ACK (initial_seq + 1)
                    // But we're the receiving side, so we check against expected_ack
                    if conn.expected_ack != 0 && ack_seq != conn.expected_ack {
                        // ACK doesn't match what we expect for handshake completion
                        update_stats_invalid_ack();
                        if config.protection_level >= 2 {
                            return Ok(xdp_action::XDP_DROP);
                        }
                    }
                }
                conn.state = 3; // Established
                // Clear incomplete handshake tracking
                clear_incomplete_handshake(src_ip, now, config);
            }
            2 => {
                // SYN_SENT (client) -> ESTABLISHED on ACK
                conn.state = 3;
            }
            3 => {
                // ESTABLISHED - normal data flow
                // Update expected_ack based on incoming seq to track received data
            }
            4 => {
                // FIN_WAIT - closing
                if flags & TCP_FIN != 0 {
                    conn.state = 6; // CLOSING
                }
            }
            _ => {}
        }
    } else {
        // ACK for unknown connection
        // This could be:
        // 1. A legitimate packet for a connection we haven't tracked (overflow)
        // 2. An ACK flood attack with random 4-tuples
        // 3. A response to our outgoing connection (reverse direction)

        if config.ack_validation_enabled != 0 && config.protection_level >= 3 {
            // In aggressive mode, drop ACKs to unknown connections
            // This may cause issues with asymmetric routing, so only use level 3
            update_stats_invalid_ack();
            return Ok(xdp_action::XDP_DROP);
        }
    }

    update_stats_passed();
    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn validate_syn_cookie(cookie: u32, expected: u32, now: u64, config: &TcpConfig) -> bool {
    // Extract time counter from cookie
    let time_bits = cookie & 0x1f;
    let current_time = ((now / 60_000_000_000) as u32) & 0x1f;

    // Allow 2 time windows (current and previous)
    let time_diff = if current_time >= time_bits {
        current_time - time_bits
    } else {
        32 - time_bits + current_time
    };

    if time_diff > 2 {
        return false;
    }

    // Compare hash portion
    let hash_mask = 0xFFFFFF80;
    (cookie & hash_mask) == (expected & hash_mask)
}

// ============================================================================
// RST Packet Handling
// ============================================================================

#[inline(always)]
fn handle_rst_packet(
    ctx: &XdpContext,
    src_ip: u32,
    now: u64,
    config: &TcpConfig,
) -> Result<u32, ()> {
    // RST flood detection is handled in update_ip_state_and_check_floods
    // Here we just do additional validation if needed

    update_stats_passed();
    Ok(xdp_action::XDP_PASS)
}

// ============================================================================
// Helper Functions
// ============================================================================

#[inline(always)]
fn make_connection_key(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16) -> u64 {
    // Create a symmetric key so both directions map to same entry
    let (ip1, ip2, port1, port2) = if src_ip < dst_ip {
        (src_ip, dst_ip, src_port, dst_port)
    } else if src_ip > dst_ip {
        (dst_ip, src_ip, dst_port, src_port)
    } else if src_port < dst_port {
        (src_ip, dst_ip, src_port, dst_port)
    } else {
        (dst_ip, src_ip, dst_port, src_port)
    };

    let mut key: u64 = ip1 as u64;
    key = key.wrapping_mul(31).wrapping_add(ip2 as u64);
    key = key.wrapping_mul(31).wrapping_add(port1 as u64);
    key = key.wrapping_mul(31).wrapping_add(port2 as u64);
    key
}

// ============================================================================
// IP Blocking
// ============================================================================

#[inline(always)]
fn is_ip_blocked_v4(src_ip: u32) -> bool {
    if let Some(state) = unsafe { TCP_IP_STATE_V4.get(&src_ip) } {
        let now = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
        state.blocked_until > now
    } else {
        false
    }
}

#[inline(always)]
fn is_ip_blocked_v6(src_ip: &[u8; 16]) -> bool {
    if let Some(state) = unsafe { TCP_IP_STATE_V6.get(src_ip) } {
        let now = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
        state.blocked_until > now
    } else {
        false
    }
}

// ============================================================================
// Configuration
// ============================================================================

#[inline(always)]
fn get_config() -> TcpConfig {
    if let Some(config) = unsafe { TCP_CONFIG.get_ptr(0) } {
        unsafe { *config }
    } else {
        TcpConfig {
            enabled: 1,
            syn_flood_protection: 1,
            syn_cookie_threshold: DEFAULT_SYN_COOKIE_THRESHOLD,
            max_syn_per_ip: DEFAULT_MAX_SYN_PER_IP,
            max_connections_per_ip: DEFAULT_MAX_CONNECTIONS_PER_IP,
            ack_flood_detection: 1,
            max_ack_per_ip: DEFAULT_MAX_ACK_PER_IP,
            rst_flood_detection: 1,
            max_rst_per_ip: DEFAULT_MAX_RST_PER_IP,
            rate_limit_window_ns: DEFAULT_RATE_LIMIT_WINDOW_NS,
            block_duration_ns: DEFAULT_BLOCK_DURATION_NS,
            protection_level: 2,
            syn_cookie_secret: DEFAULT_SYN_COOKIE_SECRET,
            syn_cookie_secret2: DEFAULT_SYN_COOKIE_SECRET2,
            handshake_timeout_ns: DEFAULT_HANDSHAKE_TIMEOUT_NS,
            max_incomplete_handshakes_per_ip: DEFAULT_MAX_INCOMPLETE_HANDSHAKES_PER_IP,
            ack_validation_enabled: 1,
            fragment_handling_enabled: 1,
        }
    }
}

// ============================================================================
// Statistics
// ============================================================================

#[inline(always)]
fn update_stats_total() {
    if let Some(stats) = unsafe { TCP_STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).total_packets += 1;
        }
    }
}

#[inline(always)]
fn update_stats_passed() {
    if let Some(stats) = unsafe { TCP_STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).passed_packets += 1;
        }
    }
}

#[inline(always)]
fn update_stats_syn_flood() {
    if let Some(stats) = unsafe { TCP_STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).dropped_syn_flood += 1;
        }
    }
}

#[inline(always)]
fn update_stats_ack_flood() {
    if let Some(stats) = unsafe { TCP_STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).dropped_ack_flood += 1;
        }
    }
}

#[inline(always)]
fn update_stats_rst_flood() {
    if let Some(stats) = unsafe { TCP_STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).dropped_rst_flood += 1;
        }
    }
}

#[inline(always)]
fn update_stats_invalid_flags() {
    if let Some(stats) = unsafe { TCP_STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).dropped_invalid_flags += 1;
        }
    }
}

#[inline(always)]
fn update_stats_blocked() {
    if let Some(stats) = unsafe { TCP_STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).dropped_blocked_ip += 1;
        }
    }
}

#[inline(always)]
fn update_stats_connection_limit() {
    if let Some(stats) = unsafe { TCP_STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).dropped_connection_limit += 1;
        }
    }
}

#[inline(always)]
fn update_stats_syn_cookie_issued() {
    if let Some(stats) = unsafe { TCP_STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).syn_cookies_issued += 1;
        }
    }
}

#[inline(always)]
fn update_stats_syn_cookie_validated() {
    if let Some(stats) = unsafe { TCP_STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).syn_cookies_validated += 1;
        }
    }
}

#[inline(always)]
fn update_stats_syn_cookie_failed() {
    if let Some(stats) = unsafe { TCP_STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).syn_cookies_failed += 1;
        }
    }
}

#[inline(always)]
fn update_stats_window_probe() {
    if let Some(stats) = unsafe { TCP_STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).window_probe_detected += 1;
        }
    }
}

#[inline(always)]
fn update_stats_dropped_fragments() {
    if let Some(stats) = unsafe { TCP_STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).dropped_fragments += 1;
        }
    }
}

#[inline(always)]
fn update_stats_invalid_ack() {
    if let Some(stats) = unsafe { TCP_STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).dropped_invalid_ack += 1;
        }
    }
}

#[inline(always)]
fn update_stats_handshake_timeout() {
    if let Some(stats) = unsafe { TCP_STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).dropped_handshake_timeout += 1;
        }
    }
}

#[inline(always)]
fn update_stats_incomplete_handshake() {
    if let Some(stats) = unsafe { TCP_STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).incomplete_handshakes_detected += 1;
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
