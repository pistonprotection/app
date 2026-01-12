//! XDP Rate Limiting Program
//!
//! Dedicated XDP program for advanced rate limiting with token bucket algorithm.

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{LruHashMap, PerCpuArray},
    programs::XdpContext,
};
use core::mem;

// Network headers

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

/// Token bucket state
#[repr(C)]
pub struct TokenBucket {
    /// Current number of tokens
    pub tokens: u64,
    /// Last update timestamp (nanoseconds)
    pub last_update: u64,
    /// Total packets from this source
    pub packets: u64,
    /// Total bytes from this source
    pub bytes: u64,
    /// Dropped packets count
    pub dropped: u64,
}

/// Rate limit configuration
#[repr(C)]
pub struct RateLimitConfig {
    /// Tokens added per second (PPS limit)
    pub tokens_per_second: u64,
    /// Maximum bucket size (burst)
    pub bucket_size: u64,
    /// Enabled flag
    pub enabled: u32,
    /// Protection level (affects strictness)
    pub level: u32,
}

/// Subnet rate limit key (for /24 or /48 limiting)
#[repr(C, packed)]
pub struct SubnetKey {
    pub prefix: u32,  // First 24 bits for IPv4
    pub padding: u32,
}

// Maps

/// Per-IP token buckets (IPv4)
#[map]
static TOKEN_BUCKETS_V4: LruHashMap<u32, TokenBucket> =
    LruHashMap::with_max_entries(2_000_000, 0);

/// Per-IP token buckets (IPv6)
#[map]
static TOKEN_BUCKETS_V6: LruHashMap<[u8; 16], TokenBucket> =
    LruHashMap::with_max_entries(1_000_000, 0);

/// Per-subnet token buckets (for broader limiting)
#[map]
static SUBNET_BUCKETS: LruHashMap<SubnetKey, TokenBucket> =
    LruHashMap::with_max_entries(100_000, 0);

/// Global configuration
#[map]
static RATELIMIT_CONFIG: PerCpuArray<RateLimitConfig> = PerCpuArray::with_max_entries(1, 0);

/// Statistics
#[map]
static RATELIMIT_STATS: PerCpuArray<RateLimitStats> = PerCpuArray::with_max_entries(1, 0);

#[repr(C)]
pub struct RateLimitStats {
    pub total_packets: u64,
    pub passed_packets: u64,
    pub dropped_packets: u64,
    pub limited_ips: u64,
}

// Constants
const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const NANOS_PER_SEC: u64 = 1_000_000_000;

/// Default rate limit values
const DEFAULT_TOKENS_PER_SEC: u64 = 1000;
const DEFAULT_BUCKET_SIZE: u64 = 2000;

#[xdp]
pub fn xdp_ratelimit(ctx: XdpContext) -> u32 {
    match try_xdp_ratelimit(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn try_xdp_ratelimit(ctx: XdpContext) -> Result<u32, ()> {
    // Check if rate limiting is enabled
    let config = get_config();
    if config.enabled == 0 {
        return Ok(xdp_action::XDP_PASS);
    }

    let data = ctx.data();
    let data_end = ctx.data_end();

    // Parse Ethernet
    if data + mem::size_of::<EthHdr>() > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let eth = unsafe { &*(data as *const EthHdr) };
    let eth_proto = u16::from_be(eth.h_proto);

    // Update stats
    update_stats_total();

    let packet_size = (data_end - data) as u64;

    match eth_proto {
        ETH_P_IP => ratelimit_ipv4(&ctx, data + mem::size_of::<EthHdr>(), data_end, packet_size, &config),
        ETH_P_IPV6 => ratelimit_ipv6(&ctx, data + mem::size_of::<EthHdr>(), data_end, packet_size, &config),
        _ => Ok(xdp_action::XDP_PASS),
    }
}

#[inline(always)]
fn ratelimit_ipv4(
    ctx: &XdpContext,
    data: usize,
    data_end: usize,
    packet_size: u64,
    config: &RateLimitConfig,
) -> Result<u32, ()> {
    if data + mem::size_of::<Ipv4Hdr>() > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip = unsafe { &*(data as *const Ipv4Hdr) };
    let src_ip = u32::from_be(ip.saddr);

    // Check per-IP rate limit
    if !check_token_bucket_v4(src_ip, packet_size, config) {
        update_stats_dropped();
        return Ok(xdp_action::XDP_DROP);
    }

    // Check subnet rate limit (optional, for DDoS from botnets)
    let subnet = SubnetKey {
        prefix: src_ip & 0xFFFFFF00, // /24 subnet
        padding: 0,
    };

    if config.level >= 2 && !check_subnet_bucket(&subnet, packet_size, config) {
        update_stats_dropped();
        return Ok(xdp_action::XDP_DROP);
    }

    update_stats_passed();
    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn ratelimit_ipv6(
    ctx: &XdpContext,
    data: usize,
    data_end: usize,
    packet_size: u64,
    config: &RateLimitConfig,
) -> Result<u32, ()> {
    if data + mem::size_of::<Ipv6Hdr>() > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip6 = unsafe { &*(data as *const Ipv6Hdr) };
    let src_ip = ip6.saddr;

    // Check per-IP rate limit
    if !check_token_bucket_v6(src_ip, packet_size, config) {
        update_stats_dropped();
        return Ok(xdp_action::XDP_DROP);
    }

    update_stats_passed();
    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn check_token_bucket_v4(ip: u32, packet_size: u64, config: &RateLimitConfig) -> bool {
    let now = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };

    if let Some(bucket) = unsafe { TOKEN_BUCKETS_V4.get_ptr_mut(&ip) } {
        let bucket = unsafe { &mut *bucket };
        return process_bucket(bucket, now, packet_size, config);
    }

    // Create new bucket for this IP
    let bucket = TokenBucket {
        tokens: config.bucket_size.saturating_sub(1),
        last_update: now,
        packets: 1,
        bytes: packet_size,
        dropped: 0,
    };
    let _ = TOKEN_BUCKETS_V4.insert(&ip, &bucket, 0);
    true
}

#[inline(always)]
fn check_token_bucket_v6(ip: [u8; 16], packet_size: u64, config: &RateLimitConfig) -> bool {
    let now = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };

    if let Some(bucket) = unsafe { TOKEN_BUCKETS_V6.get_ptr_mut(&ip) } {
        let bucket = unsafe { &mut *bucket };
        return process_bucket(bucket, now, packet_size, config);
    }

    let bucket = TokenBucket {
        tokens: config.bucket_size.saturating_sub(1),
        last_update: now,
        packets: 1,
        bytes: packet_size,
        dropped: 0,
    };
    let _ = TOKEN_BUCKETS_V6.insert(&ip, &bucket, 0);
    true
}

#[inline(always)]
fn check_subnet_bucket(subnet: &SubnetKey, packet_size: u64, config: &RateLimitConfig) -> bool {
    let now = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };

    // Subnet limits are 100x the per-IP limit
    let subnet_tokens_per_sec = config.tokens_per_second * 100;
    let subnet_bucket_size = config.bucket_size * 100;

    if let Some(bucket) = unsafe { SUBNET_BUCKETS.get_ptr_mut(subnet) } {
        let bucket = unsafe { &mut *bucket };

        let elapsed = now.saturating_sub(bucket.last_update);
        let tokens_to_add = (elapsed * subnet_tokens_per_sec) / NANOS_PER_SEC;

        bucket.tokens = core::cmp::min(bucket.tokens + tokens_to_add, subnet_bucket_size);
        bucket.last_update = now;
        bucket.packets += 1;
        bucket.bytes += packet_size;

        if bucket.tokens > 0 {
            bucket.tokens -= 1;
            true
        } else {
            bucket.dropped += 1;
            false
        }
    } else {
        let bucket = TokenBucket {
            tokens: subnet_bucket_size.saturating_sub(1),
            last_update: now,
            packets: 1,
            bytes: packet_size,
            dropped: 0,
        };
        let _ = SUBNET_BUCKETS.insert(subnet, &bucket, 0);
        true
    }
}

#[inline(always)]
fn process_bucket(bucket: &mut TokenBucket, now: u64, packet_size: u64, config: &RateLimitConfig) -> bool {
    // Calculate tokens to add based on elapsed time
    let elapsed = now.saturating_sub(bucket.last_update);
    let tokens_to_add = (elapsed * config.tokens_per_second) / NANOS_PER_SEC;

    // Refill bucket (capped at bucket_size)
    bucket.tokens = core::cmp::min(bucket.tokens + tokens_to_add, config.bucket_size);
    bucket.last_update = now;
    bucket.packets += 1;
    bucket.bytes += packet_size;

    // Check if we have tokens
    if bucket.tokens > 0 {
        bucket.tokens -= 1;
        true
    } else {
        bucket.dropped += 1;
        false
    }
}

#[inline(always)]
fn get_config() -> RateLimitConfig {
    if let Some(config) = unsafe { RATELIMIT_CONFIG.get_ptr(0) } {
        unsafe { *config }
    } else {
        RateLimitConfig {
            tokens_per_second: DEFAULT_TOKENS_PER_SEC,
            bucket_size: DEFAULT_BUCKET_SIZE,
            enabled: 1,
            level: 1,
        }
    }
}

#[inline(always)]
fn update_stats_total() {
    if let Some(stats) = unsafe { RATELIMIT_STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).total_packets += 1;
        }
    }
}

#[inline(always)]
fn update_stats_passed() {
    if let Some(stats) = unsafe { RATELIMIT_STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).passed_packets += 1;
        }
    }
}

#[inline(always)]
fn update_stats_dropped() {
    if let Some(stats) = unsafe { RATELIMIT_STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).dropped_packets += 1;
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
