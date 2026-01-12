//! XDP DDoS Filter Program
//!
//! Main XDP program for packet filtering and DDoS mitigation.

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{HashMap, LruHashMap, PerCpuArray},
    programs::XdpContext,
};
use aya_log_ebpf::info;
use core::mem;

/// IPv4 header structure
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

/// IPv6 header structure
#[repr(C)]
struct Ipv6Hdr {
    version_tc_flow: u32,
    payload_len: u16,
    nexthdr: u8,
    hop_limit: u8,
    saddr: [u8; 16],
    daddr: [u8; 16],
}

/// TCP header structure
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

/// UDP header structure
#[repr(C)]
struct UdpHdr {
    source: u16,
    dest: u16,
    len: u16,
    check: u16,
}

/// Ethernet header
#[repr(C)]
struct EthHdr {
    h_dest: [u8; 6],
    h_source: [u8; 6],
    h_proto: u16,
}

/// Rate limit entry in map
#[repr(C)]
pub struct RateLimitEntry {
    pub tokens: u64,
    pub last_update: u64,
    pub packets: u64,
    pub bytes: u64,
}

/// Blocked IP entry
#[repr(C)]
pub struct BlockedIpEntry {
    pub reason: u32,
    pub expires_at: u64,
    pub packets_blocked: u64,
}

/// Statistics counters
#[repr(C)]
pub struct Stats {
    pub packets_total: u64,
    pub packets_passed: u64,
    pub packets_dropped: u64,
    pub packets_rate_limited: u64,
    pub bytes_total: u64,
}

/// Global configuration
#[repr(C)]
#[derive(Copy, Clone)]
pub struct FilterConfig {
    pub enabled: u32,
    pub protection_level: u32,
    pub global_pps_limit: u64,
    pub per_ip_pps_limit: u64,
    pub syn_flood_protection: u32,
    pub udp_flood_protection: u32,
}

// eBPF Maps

/// Blocked IPs (IPv4)
#[map]
static BLOCKED_IPS_V4: LruHashMap<u32, BlockedIpEntry> = LruHashMap::with_max_entries(1_000_000, 0);

/// Blocked IPs (IPv6)
#[map]
static BLOCKED_IPS_V6: LruHashMap<[u8; 16], BlockedIpEntry> =
    LruHashMap::with_max_entries(500_000, 0);

/// Per-IP rate limits (IPv4)
#[map]
static RATE_LIMITS_V4: LruHashMap<u32, RateLimitEntry> = LruHashMap::with_max_entries(1_000_000, 0);

/// Per-IP rate limits (IPv6)
#[map]
static RATE_LIMITS_V6: LruHashMap<[u8; 16], RateLimitEntry> =
    LruHashMap::with_max_entries(500_000, 0);

/// Global configuration
#[map]
static CONFIG: PerCpuArray<FilterConfig> = PerCpuArray::with_max_entries(1, 0);

/// Statistics per CPU
#[map]
static STATS: PerCpuArray<Stats> = PerCpuArray::with_max_entries(1, 0);

// Constants
const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMP: u8 = 1;

// TCP flags
const TCP_SYN: u16 = 0x0002;
const TCP_ACK: u16 = 0x0010;
const TCP_RST: u16 = 0x0004;

/// Main XDP filter program
#[xdp]
pub fn xdp_filter(ctx: XdpContext) -> u32 {
    match try_xdp_filter(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn try_xdp_filter(ctx: XdpContext) -> Result<u32, ()> {
    let data = ctx.data();
    let data_end = ctx.data_end();

    // Check for minimum Ethernet header
    if data + mem::size_of::<EthHdr>() > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    // Parse Ethernet header
    let eth = unsafe { &*(data as *const EthHdr) };
    let eth_proto = u16::from_be(eth.h_proto);

    // Update stats
    if let Some(stats) = unsafe { STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).packets_total += 1;
            (*stats).bytes_total += (data_end - data) as u64;
        }
    }

    match eth_proto {
        ETH_P_IP => process_ipv4(&ctx, data + mem::size_of::<EthHdr>(), data_end),
        ETH_P_IPV6 => process_ipv6(&ctx, data + mem::size_of::<EthHdr>(), data_end),
        _ => Ok(xdp_action::XDP_PASS),
    }
}

#[inline(always)]
fn process_ipv4(ctx: &XdpContext, data: usize, data_end: usize) -> Result<u32, ()> {
    // Check for IPv4 header
    if data + mem::size_of::<Ipv4Hdr>() > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip = unsafe { &*(data as *const Ipv4Hdr) };
    let src_ip = u32::from_be(ip.saddr);

    // Check blocked list
    if let Some(blocked) = unsafe { BLOCKED_IPS_V4.get(&src_ip) } {
        // Check expiration
        let now = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
        if blocked.expires_at == 0 || blocked.expires_at > now {
            update_stats_dropped();
            return Ok(xdp_action::XDP_DROP);
        }
    }

    // Check rate limit
    if !check_rate_limit_v4(src_ip) {
        update_stats_rate_limited();
        return Ok(xdp_action::XDP_DROP);
    }

    // Protocol-specific processing
    let ihl = (ip.version_ihl & 0x0f) as usize * 4;
    let transport_offset = data + ihl;

    match ip.protocol {
        IPPROTO_TCP => process_tcp(ctx, transport_offset, data_end, src_ip),
        IPPROTO_UDP => process_udp(ctx, transport_offset, data_end, src_ip),
        IPPROTO_ICMP => process_icmp(ctx, transport_offset, data_end, src_ip),
        _ => {
            update_stats_passed();
            Ok(xdp_action::XDP_PASS)
        }
    }
}

#[inline(always)]
fn process_ipv6(ctx: &XdpContext, data: usize, data_end: usize) -> Result<u32, ()> {
    // Check for IPv6 header
    if data + mem::size_of::<Ipv6Hdr>() > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip6 = unsafe { &*(data as *const Ipv6Hdr) };
    let src_ip = ip6.saddr;

    // Check blocked list
    if let Some(blocked) = unsafe { BLOCKED_IPS_V6.get(&src_ip) } {
        let now = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
        if blocked.expires_at == 0 || blocked.expires_at > now {
            update_stats_dropped();
            return Ok(xdp_action::XDP_DROP);
        }
    }

    // Check rate limit
    if !check_rate_limit_v6(src_ip) {
        update_stats_rate_limited();
        return Ok(xdp_action::XDP_DROP);
    }

    update_stats_passed();
    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn process_tcp(ctx: &XdpContext, data: usize, data_end: usize, src_ip: u32) -> Result<u32, ()> {
    if data + mem::size_of::<TcpHdr>() > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let tcp = unsafe { &*(data as *const TcpHdr) };
    let flags = u16::from_be(tcp.doff_flags) & 0x003f;

    // SYN flood protection
    if flags == TCP_SYN {
        // Check SYN rate limit
        if let Some(config) = unsafe { CONFIG.get_ptr(0) } {
            let config = unsafe { &*config };
            if config.syn_flood_protection != 0 {
                // Additional SYN-specific rate limiting could be applied here
            }
        }
    }

    // Invalid flag combinations
    if flags == (TCP_SYN | TCP_RST) {
        update_stats_dropped();
        return Ok(xdp_action::XDP_DROP);
    }

    update_stats_passed();
    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn process_udp(ctx: &XdpContext, data: usize, data_end: usize, src_ip: u32) -> Result<u32, ()> {
    if data + mem::size_of::<UdpHdr>() > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let udp = unsafe { &*(data as *const UdpHdr) };
    let src_port = u16::from_be(udp.source);
    let dst_port = u16::from_be(udp.dest);

    // Check for amplification attack source ports
    let suspicious_ports = [53, 123, 161, 1900, 11211];
    for port in suspicious_ports {
        if src_port == port {
            // Potential amplification - apply stricter rate limiting
            if let Some(config) = unsafe { CONFIG.get_ptr(0) } {
                let config = unsafe { &*config };
                if config.udp_flood_protection != 0 {
                    // Additional UDP-specific filtering
                }
            }
        }
    }

    update_stats_passed();
    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn process_icmp(ctx: &XdpContext, data: usize, data_end: usize, src_ip: u32) -> Result<u32, ()> {
    // Basic ICMP pass-through with rate limiting applied above
    update_stats_passed();
    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn check_rate_limit_v4(src_ip: u32) -> bool {
    let now = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };

    if let Some(entry) = unsafe { RATE_LIMITS_V4.get_ptr_mut(&src_ip) } {
        let entry = unsafe { &mut *entry };

        // Token bucket algorithm
        let elapsed = now - entry.last_update;
        let tokens_to_add = elapsed / 1_000_000; // 1 token per millisecond

        entry.tokens = core::cmp::min(entry.tokens + tokens_to_add, 1000); // Max 1000 tokens
        entry.last_update = now;
        entry.packets += 1;

        if entry.tokens > 0 {
            entry.tokens -= 1;
            true
        } else {
            false
        }
    } else {
        // First packet from this IP
        let entry = RateLimitEntry {
            tokens: 999, // Start with full bucket minus this packet
            last_update: now,
            packets: 1,
            bytes: 0,
        };
        let _ = RATE_LIMITS_V4.insert(&src_ip, &entry, 0);
        true
    }
}

#[inline(always)]
fn check_rate_limit_v6(src_ip: [u8; 16]) -> bool {
    let now = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };

    if let Some(entry) = unsafe { RATE_LIMITS_V6.get_ptr_mut(&src_ip) } {
        let entry = unsafe { &mut *entry };

        let elapsed = now - entry.last_update;
        let tokens_to_add = elapsed / 1_000_000;

        entry.tokens = core::cmp::min(entry.tokens + tokens_to_add, 1000);
        entry.last_update = now;
        entry.packets += 1;

        if entry.tokens > 0 {
            entry.tokens -= 1;
            true
        } else {
            false
        }
    } else {
        let entry = RateLimitEntry {
            tokens: 999,
            last_update: now,
            packets: 1,
            bytes: 0,
        };
        let _ = RATE_LIMITS_V6.insert(&src_ip, &entry, 0);
        true
    }
}

#[inline(always)]
fn update_stats_passed() {
    if let Some(stats) = unsafe { STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).packets_passed += 1;
        }
    }
}

#[inline(always)]
fn update_stats_dropped() {
    if let Some(stats) = unsafe { STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).packets_dropped += 1;
        }
    }
}

#[inline(always)]
fn update_stats_rate_limited() {
    if let Some(stats) = unsafe { STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).packets_rate_limited += 1;
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
