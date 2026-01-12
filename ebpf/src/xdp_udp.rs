//! XDP Generic UDP Filter
//!
//! XDP program for generic UDP filtering with:
//! - Packet size validation
//! - Amplification attack detection (NTP, DNS, SSDP, Memcached, etc.)
//! - UDP flood mitigation
//! - Port scan detection
//! - Reflection attack prevention

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
// UDP Filtering Structures
// ============================================================================

/// Per-IP UDP statistics and rate limiting
#[repr(C)]
pub struct UdpIpState {
    /// Total packets from this IP
    pub packets: u64,
    /// Total bytes from this IP
    pub bytes: u64,
    /// Window start timestamp
    pub window_start: u64,
    /// Packets in current window
    pub window_packets: u64,
    /// Last seen timestamp
    pub last_seen: u64,
    /// Unique destination ports seen (port scan detection)
    pub unique_ports: u32,
    /// Amplification response packets
    pub amp_responses: u32,
    /// Blocked until timestamp
    pub blocked_until: u64,
    /// Flags
    pub flags: u32,
}

/// Per-port statistics (for detecting targeted attacks)
#[repr(C)]
pub struct UdpPortState {
    /// Packets to this port
    pub packets: u64,
    /// Unique source IPs
    pub unique_sources: u32,
    /// Window start
    pub window_start: u64,
    /// Packets in window
    pub window_packets: u64,
}

/// UDP filter configuration
#[repr(C)]
#[derive(Copy, Clone)]
pub struct UdpConfig {
    /// Filter enabled
    pub enabled: u32,
    /// Minimum UDP packet size (excluding headers)
    pub min_packet_size: u16,
    /// Maximum UDP packet size
    pub max_packet_size: u16,
    /// Rate limit window (nanoseconds)
    pub rate_limit_window_ns: u64,
    /// Maximum packets per IP per window
    pub max_packets_per_window: u64,
    /// Maximum bytes per IP per window
    pub max_bytes_per_window: u64,
    /// Block duration (nanoseconds)
    pub block_duration_ns: u64,
    /// Protection level (1=basic, 2=moderate, 3=aggressive)
    pub protection_level: u32,
    /// Enable amplification detection
    pub amp_detection_enabled: u32,
    /// Enable port scan detection
    pub portscan_detection_enabled: u32,
    /// Port scan threshold (unique ports per window)
    pub portscan_threshold: u32,
}

/// UDP statistics
#[repr(C)]
pub struct UdpStats {
    pub total_packets: u64,
    pub passed_packets: u64,
    pub dropped_rate_limited: u64,
    pub dropped_invalid_size: u64,
    pub dropped_amplification: u64,
    pub dropped_port_scan: u64,
    pub dropped_blocked_ip: u64,
    pub dropped_blocked_port: u64,
    pub dns_packets: u64,
    pub ntp_packets: u64,
    pub ssdp_packets: u64,
    pub memcached_packets: u64,
}

/// Amplification source tracking
#[repr(C)]
pub struct AmpSourceEntry {
    /// First seen timestamp
    pub first_seen: u64,
    /// Total packets
    pub packets: u64,
    /// Total response bytes
    pub response_bytes: u64,
    /// Blocked until
    pub blocked_until: u64,
}

// ============================================================================
// Constants
// ============================================================================

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const IPPROTO_UDP: u8 = 17;

// Amplification attack source ports
const PORT_DNS: u16 = 53;
const PORT_NTP: u16 = 123;
const PORT_SSDP: u16 = 1900;
const PORT_SNMP: u16 = 161;
const PORT_MEMCACHED: u16 = 11211;
const PORT_CHARGEN: u16 = 19;
const PORT_QOTD: u16 = 17;
const PORT_LDAP: u16 = 389;
const PORT_MSSQL: u16 = 1434;
const PORT_RIP: u16 = 520;
const PORT_PORTMAP: u16 = 111;
const PORT_NETBIOS: u16 = 137;
const PORT_CLDAP: u16 = 636;
const PORT_TFTP: u16 = 69;
const PORT_OPENVPN: u16 = 1194;
const PORT_STEAM: u16 = 27015;

// DNS-specific constants
const DNS_FLAG_RESPONSE: u16 = 0x8000;
const DNS_FLAG_RECURSION_AVAILABLE: u16 = 0x0080;

// NTP-specific constants
const NTP_MODE_MASK: u8 = 0x07;
const NTP_MODE_SERVER: u8 = 4;
const NTP_MODE_BROADCAST: u8 = 5;

// State flags
const FLAG_AMP_DETECTED: u32 = 0x0001;
const FLAG_PORTSCAN_DETECTED: u32 = 0x0002;
const FLAG_FLOOD_DETECTED: u32 = 0x0004;

// Default configuration
const DEFAULT_MIN_PACKET_SIZE: u16 = 0;
const DEFAULT_MAX_PACKET_SIZE: u16 = 65535;
const DEFAULT_RATE_LIMIT_WINDOW_NS: u64 = 1_000_000_000; // 1 second
const DEFAULT_MAX_PACKETS_PER_WINDOW: u64 = 1000;
const DEFAULT_MAX_BYTES_PER_WINDOW: u64 = 1_000_000; // 1MB
const DEFAULT_BLOCK_DURATION_NS: u64 = 60_000_000_000; // 60 seconds
const DEFAULT_PORTSCAN_THRESHOLD: u32 = 50;

// ============================================================================
// eBPF Maps
// ============================================================================

/// Per-IP UDP state (IPv4)
#[map]
static UDP_IP_STATE_V4: LruHashMap<u32, UdpIpState> = LruHashMap::with_max_entries(1_000_000, 0);

/// Per-IP UDP state (IPv6)
#[map]
static UDP_IP_STATE_V6: LruHashMap<[u8; 16], UdpIpState> = LruHashMap::with_max_entries(500_000, 0);

/// Per-port state (destination ports)
#[map]
static UDP_PORT_STATE: LruHashMap<u16, UdpPortState> = LruHashMap::with_max_entries(65536, 0);

/// Amplification source tracking (by source IP + source port)
#[map]
static AMP_SOURCES: LruHashMap<u64, AmpSourceEntry> = LruHashMap::with_max_entries(100_000, 0);

/// Blocked destination ports
#[map]
static BLOCKED_PORTS: HashMap<u16, u32> = HashMap::with_max_entries(1000, 0);

/// Whitelisted source IPs
#[map]
static UDP_WHITELIST: HashMap<u32, u32> = HashMap::with_max_entries(10_000, 0);

/// Protected destination ports (stricter filtering)
#[map]
static PROTECTED_PORTS: HashMap<u16, u32> = HashMap::with_max_entries(1000, 0);

/// Configuration
#[map]
static UDP_CONFIG: PerCpuArray<UdpConfig> = PerCpuArray::with_max_entries(1, 0);

/// Statistics
#[map]
static UDP_STATS: PerCpuArray<UdpStats> = PerCpuArray::with_max_entries(1, 0);

// ============================================================================
// Main XDP Entry Point
// ============================================================================

#[xdp]
pub fn xdp_udp(ctx: XdpContext) -> u32 {
    match try_xdp_udp(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn try_xdp_udp(ctx: XdpContext) -> Result<u32, ()> {
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
    config: &UdpConfig,
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
    if unsafe { UDP_WHITELIST.get(&src_ip) }.is_some() {
        return Ok(xdp_action::XDP_PASS);
    }

    // Check if IP is blocked
    if is_ip_blocked_v4(src_ip) {
        update_stats_blocked();
        return Ok(xdp_action::XDP_DROP);
    }

    let ihl = (ip.version_ihl & 0x0f) as usize * 4;
    let udp_data = data + ihl;

    process_udp(ctx, udp_data, data_end, src_ip, config)
}

// ============================================================================
// IPv6 Processing
// ============================================================================

#[inline(always)]
fn process_ipv6(
    ctx: &XdpContext,
    data: usize,
    data_end: usize,
    config: &UdpConfig,
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

    // Check if IP is blocked (using last 4 bytes as simplified key)
    if is_ip_blocked_v6(&src_ip) {
        update_stats_blocked();
        return Ok(xdp_action::XDP_DROP);
    }

    let udp_data = data + mem::size_of::<Ipv6Hdr>();

    // Use last 4 bytes as simplified IP key
    let ip_key = u32::from_be_bytes([src_ip[12], src_ip[13], src_ip[14], src_ip[15]]);

    process_udp(ctx, udp_data, data_end, ip_key, config)
}

// ============================================================================
// UDP Processing
// ============================================================================

#[inline(always)]
fn process_udp(
    ctx: &XdpContext,
    data: usize,
    data_end: usize,
    src_ip: u32,
    config: &UdpConfig,
) -> Result<u32, ()> {
    if data + mem::size_of::<UdpHdr>() > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let udp = unsafe { &*(data as *const UdpHdr) };
    let src_port = u16::from_be(udp.source);
    let dst_port = u16::from_be(udp.dest);
    let udp_len = u16::from_be(udp.len);

    // Update stats
    update_stats_total();

    // Check for blocked destination port
    if unsafe { BLOCKED_PORTS.get(&dst_port) }.is_some() {
        update_stats_blocked_port();
        return Ok(xdp_action::XDP_DROP);
    }

    // Validate packet size
    let payload_len = udp_len.saturating_sub(8); // UDP header is 8 bytes

    let min_size = if config.min_packet_size != 0 {
        config.min_packet_size
    } else {
        DEFAULT_MIN_PACKET_SIZE
    };

    let max_size = if config.max_packet_size != 0 {
        config.max_packet_size
    } else {
        DEFAULT_MAX_PACKET_SIZE
    };

    if payload_len < min_size || payload_len > max_size {
        update_stats_invalid_size();
        return Ok(xdp_action::XDP_DROP);
    }

    // Check rate limit
    let now = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };

    if !check_rate_limit_v4(src_ip, udp_len as u64, now, config) {
        update_stats_rate_limited();
        return Ok(xdp_action::XDP_DROP);
    }

    // Amplification attack detection
    if config.amp_detection_enabled != 0 {
        if let Some(action) = check_amplification_attack(
            ctx,
            data,
            data_end,
            src_ip,
            src_port,
            dst_port,
            payload_len,
            config,
        ) {
            return Ok(action);
        }
    }

    // Port scan detection
    if config.portscan_detection_enabled != 0 {
        if is_port_scan(src_ip, dst_port, now, config) {
            update_stats_port_scan();
            if config.protection_level >= 2 {
                block_ip_v4(src_ip, config.block_duration_ns);
                return Ok(xdp_action::XDP_DROP);
            }
        }
    }

    // Protocol-specific tracking (for stats)
    track_protocol_stats(src_port, dst_port);

    update_stats_passed();
    Ok(xdp_action::XDP_PASS)
}

// ============================================================================
// Amplification Attack Detection
// ============================================================================

#[inline(always)]
fn check_amplification_attack(
    ctx: &XdpContext,
    data: usize,
    data_end: usize,
    src_ip: u32,
    src_port: u16,
    dst_port: u16,
    payload_len: u16,
    config: &UdpConfig,
) -> Option<u32> {
    // Check if source port is a known amplification vector
    let is_amp_source = matches!(
        src_port,
        PORT_DNS
            | PORT_NTP
            | PORT_SSDP
            | PORT_SNMP
            | PORT_MEMCACHED
            | PORT_CHARGEN
            | PORT_QOTD
            | PORT_LDAP
            | PORT_MSSQL
            | PORT_RIP
            | PORT_PORTMAP
            | PORT_NETBIOS
            | PORT_CLDAP
            | PORT_TFTP
    );

    if !is_amp_source {
        return None;
    }

    let payload_start = data + mem::size_of::<UdpHdr>();

    // Protocol-specific validation
    match src_port {
        PORT_DNS => {
            // DNS amplification detection
            if payload_start + 12 <= data_end && payload_len > 512 {
                // Large DNS response - check if it's a response
                let flags = unsafe { u16::from_be(*((payload_start + 2) as *const u16)) };

                // Check if QR bit is set (response)
                if flags & DNS_FLAG_RESPONSE != 0 {
                    // This is a DNS response - potential amplification
                    update_stats_amplification();

                    // Track this source
                    let amp_key = ((src_ip as u64) << 16) | (src_port as u64);
                    track_amp_source(amp_key, payload_len as u64, config);

                    if config.protection_level >= 2 && payload_len > 1024 {
                        // Large DNS response - likely amplification
                        return Some(xdp_action::XDP_DROP);
                    }
                }
            }
        }

        PORT_NTP => {
            // NTP amplification detection
            if payload_start + 1 <= data_end {
                let first_byte = unsafe { *(payload_start as *const u8) };
                let mode = first_byte & NTP_MODE_MASK;

                // Check for server response or monlist response
                if mode == NTP_MODE_SERVER || mode == NTP_MODE_BROADCAST {
                    // NTP response
                    if payload_len > 48 {
                        // Larger than standard NTP response
                        update_stats_amplification();
                        track_amp_source(
                            ((src_ip as u64) << 16) | (src_port as u64),
                            payload_len as u64,
                            config,
                        );

                        if config.protection_level >= 2 && payload_len > 200 {
                            return Some(xdp_action::XDP_DROP);
                        }
                    }
                }
            }
        }

        PORT_SSDP => {
            // SSDP amplification (typically large M-SEARCH responses)
            if payload_len > 200 {
                update_stats_amplification();
                track_amp_source(
                    ((src_ip as u64) << 16) | (src_port as u64),
                    payload_len as u64,
                    config,
                );

                if config.protection_level >= 2 {
                    return Some(xdp_action::XDP_DROP);
                }
            }
        }

        PORT_MEMCACHED => {
            // Memcached amplification (can be massive)
            // Any response from memcached default port is suspicious
            update_stats_amplification();
            track_amp_source(
                ((src_ip as u64) << 16) | (src_port as u64),
                payload_len as u64,
                config,
            );

            if config.protection_level >= 1 && payload_len > 100 {
                return Some(xdp_action::XDP_DROP);
            }
        }

        PORT_CHARGEN | PORT_QOTD => {
            // These should almost never be legitimate traffic
            update_stats_amplification();
            if config.protection_level >= 1 {
                return Some(xdp_action::XDP_DROP);
            }
        }

        PORT_SNMP => {
            // SNMP amplification
            if payload_len > 200 {
                update_stats_amplification();
                track_amp_source(
                    ((src_ip as u64) << 16) | (src_port as u64),
                    payload_len as u64,
                    config,
                );

                if config.protection_level >= 2 {
                    return Some(xdp_action::XDP_DROP);
                }
            }
        }

        PORT_LDAP | PORT_CLDAP => {
            // LDAP/CLDAP amplification
            if payload_len > 100 {
                update_stats_amplification();
                track_amp_source(
                    ((src_ip as u64) << 16) | (src_port as u64),
                    payload_len as u64,
                    config,
                );

                if config.protection_level >= 2 {
                    return Some(xdp_action::XDP_DROP);
                }
            }
        }

        _ => {
            // Generic large response from known amp port
            if payload_len > 500 {
                update_stats_amplification();
                track_amp_source(
                    ((src_ip as u64) << 16) | (src_port as u64),
                    payload_len as u64,
                    config,
                );
            }
        }
    }

    None
}

#[inline(always)]
fn track_amp_source(amp_key: u64, bytes: u64, config: &UdpConfig) {
    let now = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };

    if let Some(entry) = unsafe { AMP_SOURCES.get_ptr_mut(&amp_key) } {
        let entry = unsafe { &mut *entry };
        entry.packets += 1;
        entry.response_bytes += bytes;

        // Auto-block if too many amplification packets
        if entry.packets > 100 || entry.response_bytes > 1_000_000 {
            entry.blocked_until = now + config.block_duration_ns;
        }
    } else {
        let entry = AmpSourceEntry {
            first_seen: now,
            packets: 1,
            response_bytes: bytes,
            blocked_until: 0,
        };
        let _ = AMP_SOURCES.insert(&amp_key, &entry, 0);
    }
}

// ============================================================================
// Port Scan Detection
// ============================================================================

#[inline(always)]
fn is_port_scan(src_ip: u32, dst_port: u16, now: u64, config: &UdpConfig) -> bool {
    let threshold = if config.portscan_threshold != 0 {
        config.portscan_threshold
    } else {
        DEFAULT_PORTSCAN_THRESHOLD
    };

    let window = if config.rate_limit_window_ns != 0 {
        config.rate_limit_window_ns
    } else {
        DEFAULT_RATE_LIMIT_WINDOW_NS
    };

    if let Some(state) = unsafe { UDP_IP_STATE_V4.get_ptr_mut(&src_ip) } {
        let state = unsafe { &mut *state };

        // Check if in new window
        if now.saturating_sub(state.window_start) > window {
            state.window_start = now;
            state.unique_ports = 1;
            state.flags &= !FLAG_PORTSCAN_DETECTED;
            return false;
        }

        // Simple approximation: increment unique ports counter
        // In a real implementation, you'd use a bloom filter or similar
        state.unique_ports += 1;

        if state.unique_ports > threshold {
            state.flags |= FLAG_PORTSCAN_DETECTED;
            return true;
        }
    }

    false
}

// ============================================================================
// Rate Limiting
// ============================================================================

#[inline(always)]
fn check_rate_limit_v4(src_ip: u32, bytes: u64, now: u64, config: &UdpConfig) -> bool {
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

    let max_bytes = if config.max_bytes_per_window != 0 {
        config.max_bytes_per_window
    } else {
        DEFAULT_MAX_BYTES_PER_WINDOW
    };

    if let Some(state) = unsafe { UDP_IP_STATE_V4.get_ptr_mut(&src_ip) } {
        let state = unsafe { &mut *state };

        // Check if blocked
        if state.blocked_until > now {
            return false;
        }

        // Check if in new window
        if now.saturating_sub(state.window_start) > window {
            state.window_start = now;
            state.window_packets = 1;
            state.unique_ports = 1;
            state.packets += 1;
            state.bytes += bytes;
            state.last_seen = now;
            return true;
        }

        // Update counters
        state.window_packets += 1;
        state.packets += 1;
        state.bytes += bytes;
        state.last_seen = now;

        // Check limits
        if state.window_packets > max_packets || state.bytes > max_bytes {
            state.flags |= FLAG_FLOOD_DETECTED;
            state.blocked_until = now + config.block_duration_ns;
            return false;
        }

        true
    } else {
        // First packet from this IP
        let state = UdpIpState {
            packets: 1,
            bytes,
            window_start: now,
            window_packets: 1,
            last_seen: now,
            unique_ports: 1,
            amp_responses: 0,
            blocked_until: 0,
            flags: 0,
        };
        let _ = UDP_IP_STATE_V4.insert(&src_ip, &state, 0);
        true
    }
}

#[inline(always)]
fn is_ip_blocked_v4(src_ip: u32) -> bool {
    if let Some(state) = unsafe { UDP_IP_STATE_V4.get(&src_ip) } {
        let now = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
        state.blocked_until > now
    } else {
        false
    }
}

#[inline(always)]
fn is_ip_blocked_v6(src_ip: &[u8; 16]) -> bool {
    if let Some(state) = unsafe { UDP_IP_STATE_V6.get(src_ip) } {
        let now = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
        state.blocked_until > now
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

    if let Some(state) = unsafe { UDP_IP_STATE_V4.get_ptr_mut(&src_ip) } {
        let state = unsafe { &mut *state };
        state.blocked_until = block_until;
    } else {
        let state = UdpIpState {
            packets: 0,
            bytes: 0,
            window_start: now,
            window_packets: 0,
            last_seen: now,
            unique_ports: 0,
            amp_responses: 0,
            blocked_until: block_until,
            flags: 0,
        };
        let _ = UDP_IP_STATE_V4.insert(&src_ip, &state, 0);
    }
}

// ============================================================================
// Protocol Statistics
// ============================================================================

#[inline(always)]
fn track_protocol_stats(src_port: u16, dst_port: u16) {
    if let Some(stats) = unsafe { UDP_STATS.get_ptr_mut(0) } {
        let stats = unsafe { &mut *stats };

        match src_port {
            PORT_DNS => stats.dns_packets += 1,
            PORT_NTP => stats.ntp_packets += 1,
            PORT_SSDP => stats.ssdp_packets += 1,
            PORT_MEMCACHED => stats.memcached_packets += 1,
            _ => {}
        }

        // Also check destination port
        match dst_port {
            PORT_DNS => stats.dns_packets += 1,
            PORT_NTP => stats.ntp_packets += 1,
            PORT_SSDP => stats.ssdp_packets += 1,
            PORT_MEMCACHED => stats.memcached_packets += 1,
            _ => {}
        }
    }
}

// ============================================================================
// Configuration
// ============================================================================

#[inline(always)]
fn get_config() -> UdpConfig {
    if let Some(config) = unsafe { UDP_CONFIG.get_ptr(0) } {
        unsafe { *config }
    } else {
        UdpConfig {
            enabled: 1,
            min_packet_size: DEFAULT_MIN_PACKET_SIZE,
            max_packet_size: DEFAULT_MAX_PACKET_SIZE,
            rate_limit_window_ns: DEFAULT_RATE_LIMIT_WINDOW_NS,
            max_packets_per_window: DEFAULT_MAX_PACKETS_PER_WINDOW,
            max_bytes_per_window: DEFAULT_MAX_BYTES_PER_WINDOW,
            block_duration_ns: DEFAULT_BLOCK_DURATION_NS,
            protection_level: 2,
            amp_detection_enabled: 1,
            portscan_detection_enabled: 1,
            portscan_threshold: DEFAULT_PORTSCAN_THRESHOLD,
        }
    }
}

// ============================================================================
// Statistics
// ============================================================================

#[inline(always)]
fn update_stats_total() {
    if let Some(stats) = unsafe { UDP_STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).total_packets += 1;
        }
    }
}

#[inline(always)]
fn update_stats_passed() {
    if let Some(stats) = unsafe { UDP_STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).passed_packets += 1;
        }
    }
}

#[inline(always)]
fn update_stats_rate_limited() {
    if let Some(stats) = unsafe { UDP_STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).dropped_rate_limited += 1;
        }
    }
}

#[inline(always)]
fn update_stats_invalid_size() {
    if let Some(stats) = unsafe { UDP_STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).dropped_invalid_size += 1;
        }
    }
}

#[inline(always)]
fn update_stats_amplification() {
    if let Some(stats) = unsafe { UDP_STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).dropped_amplification += 1;
        }
    }
}

#[inline(always)]
fn update_stats_port_scan() {
    if let Some(stats) = unsafe { UDP_STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).dropped_port_scan += 1;
        }
    }
}

#[inline(always)]
fn update_stats_blocked() {
    if let Some(stats) = unsafe { UDP_STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).dropped_blocked_ip += 1;
        }
    }
}

#[inline(always)]
fn update_stats_blocked_port() {
    if let Some(stats) = unsafe { UDP_STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).dropped_blocked_port += 1;
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
