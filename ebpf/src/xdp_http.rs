//! XDP HTTP Protocol Filter
//!
//! XDP program for filtering HTTP/1.1 and HTTP/2 traffic with:
//! - HTTP method validation
//! - Path/host filtering
//! - Header inspection
//! - Request rate limiting
//! - Slow HTTP attack detection (Slowloris and slow POST body)
//! - Invalid request detection
//! - HTTP/2 frame-level parsing and validation
//! - HTTP/2 Rapid Reset attack detection (CVE-2023-44487)
//! - HTTP/2 control frame rate limiting

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
// HTTP Filtering Structures
// ============================================================================

/// HTTP connection tracking state
#[repr(C)]
#[derive(Copy, Clone)]
pub struct HttpConnectionState {
    /// Connection state: 0=new, 1=request_started, 2=headers, 3=body, 4=complete
    pub state: u8,
    /// HTTP version: 1=HTTP/1.0, 2=HTTP/1.1, 3=HTTP/2
    pub http_version: u8,
    /// Request method detected
    pub method: u8,
    /// Flags for various conditions
    pub flags: u16,
    /// Timestamp of first packet in request
    pub request_start: u64,
    /// Timestamp of last packet
    pub last_seen: u64,
    /// Bytes received in current request
    pub bytes_received: u64,
    /// Headers received (for slow header attack detection)
    pub headers_bytes: u32,
    /// Number of requests from this connection
    pub request_count: u32,
    /// Expected Content-Length for POST body tracking
    pub content_length: u64,
    /// Body bytes received (for slow POST detection)
    pub body_bytes_received: u64,
    /// Timestamp when body started (for slow POST)
    pub body_start: u64,
}

/// HTTP/2 connection state tracking
#[repr(C)]
#[derive(Copy, Clone)]
pub struct Http2ConnectionState {
    /// Whether HTTP/2 preface was seen
    pub preface_seen: u8,
    /// Padding for alignment
    pub _pad: [u8; 3],
    /// RST_STREAM frames in current window
    pub rst_stream_count: u32,
    /// SETTINGS frames in current window
    pub settings_count: u32,
    /// PING frames in current window
    pub ping_count: u32,
    /// WINDOW_UPDATE frames in current window
    pub window_update_count: u32,
    /// HEADERS frames in current window
    pub headers_count: u32,
    /// Total control frames in current window
    pub control_frame_count: u32,
    /// Window start timestamp for frame rate tracking
    pub window_start: u64,
    /// Last RST_STREAM timestamp
    pub last_rst_stream: u64,
    /// Number of streams opened
    pub streams_opened: u32,
    /// Number of streams reset
    pub streams_reset: u32,
}

/// Per-IP HTTP rate limiting
#[repr(C)]
pub struct HttpRateLimit {
    /// Request count in current window
    pub requests: u64,
    /// Window start timestamp
    pub window_start: u64,
    /// Total bytes sent
    pub bytes: u64,
    /// Error count (4xx/5xx responses or invalid requests)
    pub errors: u64,
    /// Slow request count
    pub slow_requests: u32,
    /// Blocked until timestamp (0 = not blocked)
    pub blocked_until: u64,
}

/// HTTP filter configuration
#[repr(C)]
#[derive(Copy, Clone)]
pub struct HttpConfig {
    /// Filter enabled
    pub enabled: u32,
    /// HTTP port (default 80)
    pub http_port: u16,
    /// HTTPS port (default 443)
    pub https_port: u16,
    /// Maximum requests per window
    pub max_requests_per_window: u32,
    /// Window size in nanoseconds
    pub window_size_ns: u64,
    /// Maximum header size (slow loris protection)
    pub max_header_size: u32,
    /// Maximum time for headers in nanoseconds (slow loris)
    pub max_header_time_ns: u64,
    /// Maximum request body size
    pub max_body_size: u64,
    /// Block duration in nanoseconds
    pub block_duration_ns: u64,
    /// Protection level (1=basic, 2=moderate, 3=aggressive)
    pub protection_level: u32,
    /// Maximum time for body in nanoseconds (slow POST)
    pub max_body_time_ns: u64,
    /// Minimum body transfer rate in bytes per second (slow POST)
    pub min_body_rate_bps: u64,
    /// HTTP/2 max RST_STREAM frames per window (Rapid Reset protection)
    pub http2_max_rst_per_window: u32,
    /// HTTP/2 max control frames per window
    pub http2_max_control_frames_per_window: u32,
    /// HTTP/2 max streams per connection
    pub http2_max_streams: u32,
    /// HTTP/2 rapid reset detection window in nanoseconds
    pub http2_rst_window_ns: u64,
}

/// HTTP statistics
#[repr(C)]
pub struct HttpStats {
    pub total_requests: u64,
    pub passed_requests: u64,
    pub dropped_invalid_method: u64,
    pub dropped_rate_limited: u64,
    pub dropped_slow_loris: u64,
    pub dropped_invalid_request: u64,
    pub dropped_blocked_ip: u64,
    pub http2_requests: u64,
    pub dropped_slow_post: u64,
    pub dropped_http2_rapid_reset: u64,
    pub dropped_http2_control_flood: u64,
    pub http2_rst_stream_frames: u64,
    pub http2_headers_frames: u64,
    pub http2_data_frames: u64,
    pub dropped_request_smuggling: u64,
    pub dropped_header_injection: u64,
}

/// Blocked path entry (for path-based filtering)
#[repr(C)]
pub struct BlockedPath {
    /// Path hash
    pub hash: u32,
    /// Block reason
    pub reason: u32,
}

// ============================================================================
// HTTP Methods (encoded as u8)
// ============================================================================

const HTTP_METHOD_UNKNOWN: u8 = 0;
const HTTP_METHOD_GET: u8 = 1;
const HTTP_METHOD_POST: u8 = 2;
const HTTP_METHOD_PUT: u8 = 3;
const HTTP_METHOD_DELETE: u8 = 4;
const HTTP_METHOD_HEAD: u8 = 5;
const HTTP_METHOD_OPTIONS: u8 = 6;
const HTTP_METHOD_PATCH: u8 = 7;
const HTTP_METHOD_CONNECT: u8 = 8;
const HTTP_METHOD_TRACE: u8 = 9;

// HTTP/2 connection preface magic ("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
const HTTP2_PREFACE: [u8; 24] = [
    0x50, 0x52, 0x49, 0x20, 0x2a, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x32, 0x2e, 0x30, 0x0d, 0x0a,
    0x0d, 0x0a, 0x53, 0x4d, 0x0d, 0x0a, 0x0d, 0x0a,
];

// HTTP/2 Frame Types (RFC 7540 Section 6)
const HTTP2_FRAME_DATA: u8 = 0x0;
const HTTP2_FRAME_HEADERS: u8 = 0x1;
const HTTP2_FRAME_PRIORITY: u8 = 0x2;
const HTTP2_FRAME_RST_STREAM: u8 = 0x3;
const HTTP2_FRAME_SETTINGS: u8 = 0x4;
const HTTP2_FRAME_PUSH_PROMISE: u8 = 0x5;
const HTTP2_FRAME_PING: u8 = 0x6;
const HTTP2_FRAME_GOAWAY: u8 = 0x7;
const HTTP2_FRAME_WINDOW_UPDATE: u8 = 0x8;
const HTTP2_FRAME_CONTINUATION: u8 = 0x9;

// HTTP/2 Frame Header size (9 bytes)
const HTTP2_FRAME_HEADER_SIZE: usize = 9;

// HTTP/2 Frame Flags
const HTTP2_FLAG_END_STREAM: u8 = 0x1;
const HTTP2_FLAG_END_HEADERS: u8 = 0x4;

// Connection flags
const FLAG_SLOW_HEADERS: u16 = 0x0001;
const FLAG_SLOW_BODY: u16 = 0x0002;
const FLAG_INVALID_METHOD: u16 = 0x0004;
const FLAG_HTTP2: u16 = 0x0008;
const FLAG_SUSPICIOUS: u16 = 0x0010;
const FLAG_HAS_CONTENT_LENGTH: u16 = 0x0020;
const FLAG_IN_BODY: u16 = 0x0040;
const FLAG_HAS_TRANSFER_ENCODING: u16 = 0x0080;
const FLAG_SMUGGLING_DETECTED: u16 = 0x0100;
const FLAG_DUPLICATE_CL: u16 = 0x0200;

// ============================================================================
// eBPF Maps
// ============================================================================

/// HTTP connection state tracking (keyed by src_ip:src_port:dst_port)
#[map]
static HTTP_CONNECTIONS: LruHashMap<u64, HttpConnectionState> =
    LruHashMap::with_max_entries(1_000_000, 0);

/// HTTP/2 connection state tracking (keyed by src_ip:src_port:dst_port)
#[map]
static HTTP2_CONNECTIONS: LruHashMap<u64, Http2ConnectionState> =
    LruHashMap::with_max_entries(500_000, 0);

/// Per-IP rate limiting
#[map]
static HTTP_RATE_LIMITS: LruHashMap<u32, HttpRateLimit> = LruHashMap::with_max_entries(500_000, 0);

/// Per-IP rate limiting for IPv6
#[map]
static HTTP_RATE_LIMITS_V6: LruHashMap<[u8; 16], HttpRateLimit> =
    LruHashMap::with_max_entries(250_000, 0);

/// Blocked paths (by hash)
#[map]
static BLOCKED_PATHS: HashMap<u32, BlockedPath> = HashMap::with_max_entries(10_000, 0);

/// Blocked User-Agent hashes
#[map]
static BLOCKED_USER_AGENTS: HashMap<u32, u32> = HashMap::with_max_entries(10_000, 0);

/// Whitelisted IPs (bypass filtering)
#[map]
static HTTP_WHITELIST: HashMap<u32, u32> = HashMap::with_max_entries(10_000, 0);

/// Configuration
#[map]
static HTTP_CONFIG: PerCpuArray<HttpConfig> = PerCpuArray::with_max_entries(1, 0);

/// Statistics
#[map]
static HTTP_STATS: PerCpuArray<HttpStats> = PerCpuArray::with_max_entries(1, 0);

// ============================================================================
// Constants
// ============================================================================

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const IPPROTO_TCP: u8 = 6;

const DEFAULT_HTTP_PORT: u16 = 80;
const DEFAULT_HTTPS_PORT: u16 = 443;

// Default limits
const DEFAULT_MAX_REQUESTS_PER_WINDOW: u32 = 100;
const DEFAULT_WINDOW_SIZE_NS: u64 = 1_000_000_000; // 1 second
const DEFAULT_MAX_HEADER_SIZE: u32 = 8192;
const DEFAULT_MAX_HEADER_TIME_NS: u64 = 10_000_000_000; // 10 seconds
const DEFAULT_MAX_BODY_SIZE: u64 = 10_485_760; // 10MB
const DEFAULT_BLOCK_DURATION_NS: u64 = 60_000_000_000; // 60 seconds
const DEFAULT_MAX_BODY_TIME_NS: u64 = 120_000_000_000; // 120 seconds for body
const DEFAULT_MIN_BODY_RATE_BPS: u64 = 1024; // 1KB/s minimum transfer rate

// HTTP/2 specific limits (CVE-2023-44487 Rapid Reset protection)
const DEFAULT_HTTP2_MAX_RST_PER_WINDOW: u32 = 100; // Max RST_STREAM frames per window
const DEFAULT_HTTP2_RST_WINDOW_NS: u64 = 1_000_000_000; // 1 second window
const DEFAULT_HTTP2_MAX_CONTROL_FRAMES_PER_WINDOW: u32 = 1000; // Max control frames
const DEFAULT_HTTP2_MAX_STREAMS: u32 = 100; // Max concurrent streams

// ============================================================================
// Main XDP Entry Point
// ============================================================================

#[xdp]
pub fn xdp_http(ctx: XdpContext) -> u32 {
    match try_xdp_http(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn try_xdp_http(ctx: XdpContext) -> Result<u32, ()> {
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
    config: &HttpConfig,
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

    // Check whitelist
    if unsafe { HTTP_WHITELIST.get(&src_ip) }.is_some() {
        return Ok(xdp_action::XDP_PASS);
    }

    // Check if IP is blocked
    if is_ip_blocked_v4(src_ip) {
        update_stats_blocked();
        return Ok(xdp_action::XDP_DROP);
    }

    let ihl = (ip.version_ihl & 0x0f) as usize * 4;
    let tcp_data = data + ihl;

    process_tcp_http(ctx, tcp_data, data_end, src_ip, config)
}

// ============================================================================
// IPv6 Processing
// ============================================================================

#[inline(always)]
fn process_ipv6(
    ctx: &XdpContext,
    data: usize,
    data_end: usize,
    config: &HttpConfig,
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

    // For IPv6, we use a simplified check - convert to u32 key for connection tracking
    let ip_key = u32::from_be_bytes([src_ip[12], src_ip[13], src_ip[14], src_ip[15]]);

    process_tcp_http(ctx, tcp_data, data_end, ip_key, config)
}

// ============================================================================
// TCP/HTTP Processing
// ============================================================================

#[inline(always)]
fn process_tcp_http(
    _ctx: &XdpContext,
    data: usize,
    data_end: usize,
    src_ip: u32,
    config: &HttpConfig,
) -> Result<u32, ()> {
    if data + mem::size_of::<TcpHdr>() > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let tcp = unsafe { &*(data as *const TcpHdr) };
    let dst_port = u16::from_be(tcp.dest);
    let src_port = u16::from_be(tcp.source);

    // Check if this is HTTP/HTTPS traffic
    let http_port = if config.http_port != 0 {
        config.http_port
    } else {
        DEFAULT_HTTP_PORT
    };
    let https_port = if config.https_port != 0 {
        config.https_port
    } else {
        DEFAULT_HTTPS_PORT
    };

    if dst_port != http_port && dst_port != https_port {
        return Ok(xdp_action::XDP_PASS);
    }

    // Update total request stats
    update_stats_total();

    // Check rate limit first
    if !check_rate_limit_v4(src_ip, config) {
        update_stats_rate_limited();
        return Ok(xdp_action::XDP_DROP);
    }

    // Calculate TCP payload
    let tcp_header_len = ((u16::from_be(tcp.doff_flags) >> 12) & 0x0f) as usize * 4;
    let payload_start = data + tcp_header_len;

    if payload_start >= data_end {
        // No payload (SYN, ACK, FIN, etc.) - pass through
        return Ok(xdp_action::XDP_PASS);
    }

    let payload_len = data_end - payload_start;
    if payload_len == 0 {
        return Ok(xdp_action::XDP_PASS);
    }

    // Connection tracking key
    let conn_key = make_connection_key(src_ip, src_port, dst_port);
    let now = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };

    // Get or create connection state
    let _conn_state = get_or_create_connection(conn_key, now);

    // Validate HTTP request payload
    let payload = unsafe {
        core::slice::from_raw_parts(payload_start as *const u8, core::cmp::min(payload_len, 512))
    };

    // Check for HTTP/2 preface or existing HTTP/2 connection
    if payload_len >= 24 && is_http2_preface(payload) {
        update_stats_http2();
        // Initialize HTTP/2 connection state
        let _ = get_or_create_http2_connection(conn_key, now);
        return Ok(xdp_action::XDP_PASS);
    }

    // Check if this is an existing HTTP/2 connection with frame data
    if let Some(h2_state) = unsafe { HTTP2_CONNECTIONS.get(&conn_key) } {
        if h2_state.preface_seen == 1 {
            // Process HTTP/2 frames
            return process_http2_frames(payload, payload_len, conn_key, src_ip, config, now);
        }
    }

    // Check for slow HTTP attack (slow loris / slow POST)
    if let Some(state) = unsafe { HTTP_CONNECTIONS.get_ptr_mut(&conn_key) } {
        let state = unsafe { &mut *state };

        // Update connection state
        state.last_seen = now;
        state.bytes_received += payload_len as u64;

        // Check for slow loris attack (headers taking too long)
        let max_header_time = if config.max_header_time_ns != 0 {
            config.max_header_time_ns
        } else {
            DEFAULT_MAX_HEADER_TIME_NS
        };

        if state.state == 1 || state.state == 2 {
            // In headers phase
            state.headers_bytes += payload_len as u32;

            let elapsed = now.saturating_sub(state.request_start);
            if elapsed > max_header_time {
                // Slow loris detected
                state.flags |= FLAG_SLOW_HEADERS;
                block_ip_v4(src_ip, config.block_duration_ns);
                update_stats_slow_loris();
                return Ok(xdp_action::XDP_DROP);
            }

            // Check max header size
            let max_header_size = if config.max_header_size != 0 {
                config.max_header_size
            } else {
                DEFAULT_MAX_HEADER_SIZE
            };

            if state.headers_bytes > max_header_size {
                update_stats_invalid();
                return Ok(xdp_action::XDP_DROP);
            }

            // Check for end of headers (look for \r\n\r\n)
            if check_headers_complete(payload) {
                state.state = 3; // Move to body phase
                state.body_start = now;
                // Parse Content-Length if present
                if let Some(content_len) = parse_content_length(payload) {
                    state.content_length = content_len;
                    state.flags |= FLAG_HAS_CONTENT_LENGTH;
                }
            }
        } else if state.state == 3 {
            // In body phase - check for slow POST attack
            state.body_bytes_received += payload_len as u64;
            state.flags |= FLAG_IN_BODY;

            // Check slow POST attack (body taking too long with low transfer rate)
            if state.flags & FLAG_HAS_CONTENT_LENGTH != 0 && state.content_length > 0 {
                let body_elapsed = now.saturating_sub(state.body_start);
                let max_body_time = if config.max_body_time_ns != 0 {
                    config.max_body_time_ns
                } else {
                    DEFAULT_MAX_BODY_TIME_NS
                };

                // Check if body transfer is taking too long
                if body_elapsed > max_body_time {
                    state.flags |= FLAG_SLOW_BODY;
                    block_ip_v4(src_ip, config.block_duration_ns);
                    update_stats_slow_post();
                    return Ok(xdp_action::XDP_DROP);
                }

                // Check minimum transfer rate (bytes per second)
                if body_elapsed > 1_000_000_000 {
                    // After 1 second, check rate
                    // Use >> 30 to approximate division by 1 billion (2^30 ≈ 1.07B)
                    // This avoids 128-bit math that eBPF doesn't support
                    let elapsed_secs = body_elapsed >> 30;
                    if elapsed_secs == 0 {
                        return Ok(xdp_action::XDP_PASS); // Avoid division by zero
                    }
                    let min_rate = if config.min_body_rate_bps != 0 {
                        config.min_body_rate_bps
                    } else {
                        DEFAULT_MIN_BODY_RATE_BPS
                    };

                    let actual_rate = state.body_bytes_received / elapsed_secs;
                    if actual_rate < min_rate && state.body_bytes_received < state.content_length {
                        // Transfer rate too slow - likely slow POST attack
                        state.flags |= FLAG_SLOW_BODY;
                        block_ip_v4(src_ip, config.block_duration_ns);
                        update_stats_slow_post();
                        return Ok(xdp_action::XDP_DROP);
                    }
                }

                // Check max body size
                let max_body_size = if config.max_body_size != 0 {
                    config.max_body_size
                } else {
                    DEFAULT_MAX_BODY_SIZE
                };

                if state.body_bytes_received > max_body_size {
                    update_stats_invalid();
                    return Ok(xdp_action::XDP_DROP);
                }
            }
        }
    }

    // Validate HTTP/1.x request (only for new requests, not continuation data)
    match validate_http_request(payload, config) {
        HttpValidation::Valid(method) => {
            if let Some(state) = unsafe { HTTP_CONNECTIONS.get_ptr_mut(&conn_key) } {
                let state = unsafe { &mut *state };
                state.method = method;
                state.state = 2; // Headers phase
                state.request_count += 1;
            }
            update_stats_passed();
            Ok(xdp_action::XDP_PASS)
        }
        HttpValidation::InvalidMethod => {
            update_stats_invalid_method();
            if config.protection_level >= 2 {
                block_ip_v4(src_ip, config.block_duration_ns);
            }
            Ok(xdp_action::XDP_DROP)
        }
        HttpValidation::InvalidRequest => {
            update_stats_invalid();
            if config.protection_level >= 3 {
                block_ip_v4(src_ip, (config.block_duration_ns >> 1));
            }
            Ok(xdp_action::XDP_DROP)
        }
        HttpValidation::RequestSmuggling => {
            // Request smuggling detected - block and log
            update_stats_request_smuggling();
            if let Some(state) = unsafe { HTTP_CONNECTIONS.get_ptr_mut(&conn_key) } {
                let state = unsafe { &mut *state };
                state.flags |= FLAG_SMUGGLING_DETECTED;
            }
            // Block IP for longer duration - smuggling is a serious attack
            block_ip_v4(src_ip, (config.block_duration_ns << 1));
            Ok(xdp_action::XDP_DROP)
        }
        HttpValidation::Suspicious => {
            // Mark as suspicious but allow (for logging)
            if let Some(state) = unsafe { HTTP_CONNECTIONS.get_ptr_mut(&conn_key) } {
                let state = unsafe { &mut *state };
                state.flags |= FLAG_SUSPICIOUS;
            }
            update_stats_passed();
            Ok(xdp_action::XDP_PASS)
        }
        HttpValidation::NotHttp => {
            // Not an HTTP request line - could be continuation data
            Ok(xdp_action::XDP_PASS)
        }
    }
}

// ============================================================================
// HTTP/2 Frame Processing
// ============================================================================

/// HTTP/2 frame header structure (9 bytes)
/// - 3 bytes: length (24 bits)
/// - 1 byte: type
/// - 1 byte: flags
/// - 4 bytes: stream ID (R bit + 31 bits)
#[repr(C, packed)]
struct Http2FrameHeader {
    length_high: u8,
    length_mid: u8,
    length_low: u8,
    frame_type: u8,
    flags: u8,
    stream_id: [u8; 4],
}

#[inline(always)]
fn get_or_create_http2_connection(conn_key: u64, now: u64) -> Http2ConnectionState {
    if let Some(state) = unsafe { HTTP2_CONNECTIONS.get(&conn_key) } {
        *state
    } else {
        let state = Http2ConnectionState {
            preface_seen: 1,
            _pad: [0; 3],
            rst_stream_count: 0,
            settings_count: 0,
            ping_count: 0,
            window_update_count: 0,
            headers_count: 0,
            control_frame_count: 0,
            window_start: now,
            last_rst_stream: 0,
            streams_opened: 0,
            streams_reset: 0,
        };
        let _ = HTTP2_CONNECTIONS.insert(&conn_key, &state, 0);
        state
    }
}

#[inline(always)]
fn process_http2_frames(
    payload: &[u8],
    payload_len: usize,
    conn_key: u64,
    src_ip: u32,
    config: &HttpConfig,
    now: u64,
) -> Result<u32, ()> {
    // Need at least a frame header
    if payload_len < HTTP2_FRAME_HEADER_SIZE {
        return Ok(xdp_action::XDP_PASS);
    }

    // Parse frame header
    let frame_header = unsafe { &*(payload.as_ptr() as *const Http2FrameHeader) };
    let frame_length = ((frame_header.length_high as u32) << 16)
        | ((frame_header.length_mid as u32) << 8)
        | (frame_header.length_low as u32);
    let frame_type = frame_header.frame_type;
    let _frame_flags = frame_header.flags;
    let _stream_id = u32::from_be_bytes(frame_header.stream_id) & 0x7FFFFFFF; // Clear reserved bit

    // Get or create HTTP/2 connection state
    if let Some(h2_state) = unsafe { HTTP2_CONNECTIONS.get_ptr_mut(&conn_key) } {
        let h2_state = unsafe { &mut *h2_state };

        // Check if we need to reset the window
        let rst_window = if config.http2_rst_window_ns != 0 {
            config.http2_rst_window_ns
        } else {
            DEFAULT_HTTP2_RST_WINDOW_NS
        };

        if now.saturating_sub(h2_state.window_start) > rst_window {
            // Reset counters for new window
            h2_state.window_start = now;
            h2_state.rst_stream_count = 0;
            h2_state.settings_count = 0;
            h2_state.ping_count = 0;
            h2_state.window_update_count = 0;
            h2_state.headers_count = 0;
            h2_state.control_frame_count = 0;
        }

        // Process frame by type
        match frame_type {
            HTTP2_FRAME_DATA => {
                update_stats_http2_data();
                // DATA frames are not control frames, allow through
            }
            HTTP2_FRAME_HEADERS => {
                update_stats_http2_headers();
                h2_state.headers_count += 1;
                h2_state.streams_opened += 1;
                h2_state.control_frame_count += 1;

                // Check max streams
                let max_streams = if config.http2_max_streams != 0 {
                    config.http2_max_streams
                } else {
                    DEFAULT_HTTP2_MAX_STREAMS
                };

                if h2_state.streams_opened > max_streams {
                    update_stats_http2_control_flood();
                    block_ip_v4(src_ip, config.block_duration_ns);
                    return Ok(xdp_action::XDP_DROP);
                }
            }
            HTTP2_FRAME_RST_STREAM => {
                update_stats_http2_rst_stream();
                h2_state.rst_stream_count += 1;
                h2_state.streams_reset += 1;
                h2_state.control_frame_count += 1;
                h2_state.last_rst_stream = now;

                // CVE-2023-44487: Rapid Reset Attack Detection
                // Attackers send HEADERS followed immediately by RST_STREAM
                let max_rst = if config.http2_max_rst_per_window != 0 {
                    config.http2_max_rst_per_window
                } else {
                    DEFAULT_HTTP2_MAX_RST_PER_WINDOW
                };

                if h2_state.rst_stream_count > max_rst {
                    update_stats_http2_rapid_reset();
                    block_ip_v4(src_ip, (config.block_duration_ns << 1)); // Longer block for rapid reset
                    return Ok(xdp_action::XDP_DROP);
                }

                // Additional heuristic: ratio of RST to HEADERS
                // If more streams are being reset than opened, suspicious
                if h2_state.streams_reset > h2_state.streams_opened && h2_state.streams_reset > 10 {
                    update_stats_http2_rapid_reset();
                    block_ip_v4(src_ip, (config.block_duration_ns << 1));
                    return Ok(xdp_action::XDP_DROP);
                }
            }
            HTTP2_FRAME_SETTINGS => {
                h2_state.settings_count += 1;
                h2_state.control_frame_count += 1;
            }
            HTTP2_FRAME_PING => {
                h2_state.ping_count += 1;
                h2_state.control_frame_count += 1;
            }
            HTTP2_FRAME_WINDOW_UPDATE => {
                h2_state.window_update_count += 1;
                h2_state.control_frame_count += 1;
            }
            HTTP2_FRAME_PRIORITY
            | HTTP2_FRAME_PUSH_PROMISE
            | HTTP2_FRAME_GOAWAY
            | HTTP2_FRAME_CONTINUATION => {
                h2_state.control_frame_count += 1;
            }
            _ => {
                // Unknown frame type - could be extension, allow but count
                h2_state.control_frame_count += 1;
            }
        }

        // Check control frame flood
        let max_control_frames = if config.http2_max_control_frames_per_window != 0 {
            config.http2_max_control_frames_per_window
        } else {
            DEFAULT_HTTP2_MAX_CONTROL_FRAMES_PER_WINDOW
        };

        if h2_state.control_frame_count > max_control_frames {
            update_stats_http2_control_flood();
            block_ip_v4(src_ip, config.block_duration_ns);
            return Ok(xdp_action::XDP_DROP);
        }
    }

    // Validate frame length (max frame size is 16384 by default, can be up to 16MB)
    if frame_length > 16777215 {
        update_stats_invalid();
        return Ok(xdp_action::XDP_DROP);
    }

    Ok(xdp_action::XDP_PASS)
}

/// Check if headers are complete (look for \r\n\r\n sequence)
#[inline(always)]
fn check_headers_complete(payload: &[u8]) -> bool {
    let scan_limit = core::cmp::min(payload.len(), 512);
    for i in 0..scan_limit.saturating_sub(3) {
        if payload[i] == b'\r'
            && payload.get(i + 1) == Some(&b'\n')
            && payload.get(i + 2) == Some(&b'\r')
            && payload.get(i + 3) == Some(&b'\n')
        {
            return true;
        }
    }
    false
}

/// Parse Content-Length header value
#[inline(always)]
fn parse_content_length(payload: &[u8]) -> Option<u64> {
    // Look for "Content-Length:" (case-insensitive would be ideal but we do case-sensitive for performance)
    let scan_limit = core::cmp::min(payload.len(), 512);

    // Search for "Content-Length: " or "content-length: "
    for i in 0..scan_limit.saturating_sub(16) {
        let matches_upper = payload[i] == b'C'
            && payload.get(i + 1) == Some(&b'o')
            && payload.get(i + 2) == Some(&b'n')
            && payload.get(i + 3) == Some(&b't')
            && payload.get(i + 4) == Some(&b'e')
            && payload.get(i + 5) == Some(&b'n')
            && payload.get(i + 6) == Some(&b't')
            && payload.get(i + 7) == Some(&b'-')
            && payload.get(i + 8) == Some(&b'L')
            && payload.get(i + 9) == Some(&b'e')
            && payload.get(i + 10) == Some(&b'n')
            && payload.get(i + 11) == Some(&b'g')
            && payload.get(i + 12) == Some(&b't')
            && payload.get(i + 13) == Some(&b'h')
            && payload.get(i + 14) == Some(&b':');

        let matches_lower = payload[i] == b'c'
            && payload.get(i + 1) == Some(&b'o')
            && payload.get(i + 2) == Some(&b'n')
            && payload.get(i + 3) == Some(&b't')
            && payload.get(i + 4) == Some(&b'e')
            && payload.get(i + 5) == Some(&b'n')
            && payload.get(i + 6) == Some(&b't')
            && payload.get(i + 7) == Some(&b'-')
            && payload.get(i + 8) == Some(&b'l')
            && payload.get(i + 9) == Some(&b'e')
            && payload.get(i + 10) == Some(&b'n')
            && payload.get(i + 11) == Some(&b'g')
            && payload.get(i + 12) == Some(&b't')
            && payload.get(i + 13) == Some(&b'h')
            && payload.get(i + 14) == Some(&b':');

        if matches_upper || matches_lower {
            // Found Content-Length header, parse the value
            let value_start = i + 15;
            // Skip whitespace
            let mut pos = value_start;
            while pos < scan_limit && payload.get(pos) == Some(&b' ') {
                pos += 1;
            }

            // Parse digits
            let mut value: u64 = 0;
            while pos < scan_limit {
                if let Some(&c) = payload.get(pos) {
                    if c >= b'0' && c <= b'9' {
                        value = value.saturating_mul(10).saturating_add((c - b'0') as u64);
                        pos += 1;
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }

            if value > 0 {
                return Some(value);
            }
        }
    }

    None
}

// ============================================================================
// HTTP Request Smuggling Detection
// ============================================================================

/// Result of HTTP smuggling checks
struct SmugglingCheckResult {
    /// Whether smuggling indicators were found
    pub smuggling_detected: bool,
    /// Whether both Content-Length and Transfer-Encoding are present
    pub cl_te_conflict: bool,
    /// Whether duplicate Content-Length headers with different values exist
    pub duplicate_cl: bool,
    /// Whether Transfer-Encoding has obfuscated value
    pub obfuscated_te: bool,
    /// Content-Length value (if found)
    pub content_length: Option<u64>,
}

/// Check for HTTP request smuggling indicators
///
/// HTTP request smuggling attacks exploit discrepancies in how different
/// servers interpret ambiguous requests. Common vectors include:
///
/// 1. CL.TE: Request has both Content-Length and Transfer-Encoding headers
///    - Some servers prioritize Content-Length, others Transfer-Encoding
///    - Attacker can hide a second request in the body
///
/// 2. TE.CL: Same concept but exploits reversed priority
///
/// 3. TE.TE: Obfuscated Transfer-Encoding (spaces, capitalization, etc.)
///    - One server recognizes it, another doesn't
///
/// 4. Duplicate Content-Length headers with different values
///    - Servers may take first, last, or reject
///
/// 5. Invalid Transfer-Encoding values
///    - Some servers ignore invalid values, others don't
#[inline(always)]
fn check_request_smuggling(payload: &[u8]) -> SmugglingCheckResult {
    let mut result = SmugglingCheckResult {
        smuggling_detected: false,
        cl_te_conflict: false,
        duplicate_cl: false,
        obfuscated_te: false,
        content_length: None,
    };

    let scan_limit = core::cmp::min(payload.len(), 2048);
    let mut content_length_count = 0;
    let mut first_content_length: Option<u64> = None;
    let mut has_transfer_encoding = false;
    let mut has_chunked = false;

    // Scan for headers
    let mut i = 0;
    while i < scan_limit.saturating_sub(16) {
        // Look for end of request line first (find \r\n)
        if i == 0 {
            // Skip the request line
            while i < scan_limit.saturating_sub(1) {
                if payload[i] == b'\r' && payload.get(i + 1) == Some(&b'\n') {
                    i += 2;
                    break;
                }
                i += 1;
            }
            continue;
        }

        // Check for end of headers
        if payload[i] == b'\r' && payload.get(i + 1) == Some(&b'\n') {
            if payload.get(i + 2) == Some(&b'\r') && payload.get(i + 3) == Some(&b'\n') {
                break; // End of headers
            }
        }

        // Check for Content-Length header (case variations)
        if check_header_name_ci(payload, i, b"content-length") {
            content_length_count += 1;

            // Parse the value
            let value_start = i + 15; // "content-length:" length
            if let Some(cl) = parse_header_value_u64(payload, value_start, scan_limit) {
                if first_content_length.is_none() {
                    first_content_length = Some(cl);
                    result.content_length = Some(cl);
                } else if first_content_length != Some(cl) {
                    // Different Content-Length values - smuggling indicator!
                    result.duplicate_cl = true;
                    result.smuggling_detected = true;
                }
            }
        }

        // Check for Transfer-Encoding header (case variations and obfuscation)
        if check_header_name_ci(payload, i, b"transfer-encoding") {
            has_transfer_encoding = true;

            // Check the value for "chunked" (with possible obfuscation)
            let value_start = i + 18; // "transfer-encoding:" length
            if check_te_value_chunked(payload, value_start, scan_limit) {
                has_chunked = true;
            }

            // Check for obfuscated Transfer-Encoding
            // Common obfuscation: extra spaces, weird capitalization, newlines
            if check_te_obfuscation(payload, i, scan_limit) {
                result.obfuscated_te = true;
                result.smuggling_detected = true;
            }
        }

        // Check for header injection via newlines in values
        // This can be used for response splitting or smuggling
        if check_header_injection(payload, i, scan_limit) {
            result.smuggling_detected = true;
        }

        // Move to next line
        while i < scan_limit.saturating_sub(1) {
            if payload[i] == b'\r' && payload.get(i + 1) == Some(&b'\n') {
                i += 2;
                break;
            }
            i += 1;
        }
    }

    // CL.TE/TE.CL conflict detection
    if content_length_count > 0 && has_transfer_encoding {
        result.cl_te_conflict = true;
        result.smuggling_detected = true;
    }

    // Duplicate Content-Length without Transfer-Encoding is also suspicious
    if content_length_count > 1 {
        result.duplicate_cl = true;
        result.smuggling_detected = true;
    }

    result
}

/// Check if a header name matches (case-insensitive)
#[inline(always)]
fn check_header_name_ci(payload: &[u8], pos: usize, name: &[u8]) -> bool {
    if pos + name.len() >= payload.len() {
        return false;
    }

    for j in 0..name.len() {
        let c = payload[pos + j];
        let expected = name[j];

        // Case-insensitive comparison
        let c_lower = if c >= b'A' && c <= b'Z' { c + 32 } else { c };
        let expected_lower = if expected >= b'A' && expected <= b'Z' {
            expected + 32
        } else {
            expected
        };

        if c_lower != expected_lower {
            return false;
        }
    }

    // Check for colon or colon with space after header name
    let next = payload.get(pos + name.len());
    next == Some(&b':') || next == Some(&b' ')
}

/// Parse a u64 value from header value position
#[inline(always)]
fn parse_header_value_u64(payload: &[u8], start: usize, limit: usize) -> Option<u64> {
    let mut pos = start;

    // Skip colon and whitespace
    while pos < limit {
        let c = payload.get(pos)?;
        if *c == b':' || *c == b' ' || *c == b'\t' {
            pos += 1;
        } else {
            break;
        }
    }

    // Parse digits
    let mut value: u64 = 0;
    let mut found_digit = false;

    while pos < limit {
        let c = payload.get(pos)?;
        if *c >= b'0' && *c <= b'9' {
            value = value.saturating_mul(10).saturating_add((*c - b'0') as u64);
            found_digit = true;
            pos += 1;
        } else {
            break;
        }
    }

    if found_digit { Some(value) } else { None }
}

/// Check if Transfer-Encoding value contains "chunked"
#[inline(always)]
fn check_te_value_chunked(payload: &[u8], start: usize, limit: usize) -> bool {
    let mut pos = start;

    // Skip colon and whitespace
    while pos < limit {
        if let Some(&c) = payload.get(pos) {
            if c == b':' || c == b' ' || c == b'\t' {
                pos += 1;
            } else {
                break;
            }
        } else {
            return false;
        }
    }

    // Look for "chunked" (case-insensitive)
    let chunked = b"chunked";
    if pos + 7 > limit {
        return false;
    }

    for i in 0..7 {
        if let Some(&c) = payload.get(pos + i) {
            let c_lower = if c >= b'A' && c <= b'Z' { c + 32 } else { c };
            if c_lower != chunked[i] {
                return false;
            }
        } else {
            return false;
        }
    }

    true
}

/// Check for Transfer-Encoding header obfuscation
#[inline(always)]
fn check_te_obfuscation(payload: &[u8], start: usize, limit: usize) -> bool {
    // Common obfuscation patterns:
    // - Extra whitespace: "Transfer-Encoding : chunked"
    // - Tab characters: "Transfer-Encoding:\tchunked"
    // - Line folding: "Transfer-Encoding:\r\n chunked" (deprecated but some servers accept)
    // - Multiple values: "Transfer-Encoding: chunked, identity"

    let mut pos = start;

    // Find the colon
    while pos < limit {
        if let Some(&c) = payload.get(pos) {
            if c == b':' {
                pos += 1;
                break;
            }
            if c == b' ' || c == b'\t' {
                // Space before colon is obfuscation
                return true;
            }
            pos += 1;
        } else {
            return false;
        }
    }

    // Check for obfuscation after colon
    let mut space_count = 0;
    let mut has_tab = false;
    let mut has_line_fold = false;

    while pos < limit.saturating_sub(2) {
        if let Some(&c) = payload.get(pos) {
            if c == b' ' {
                space_count += 1;
            } else if c == b'\t' {
                has_tab = true;
            } else if c == b'\r' {
                if payload.get(pos + 1) == Some(&b'\n') {
                    if payload.get(pos + 2) == Some(&b' ') || payload.get(pos + 2) == Some(&b'\t') {
                        // Line folding (obs-fold) - deprecated but possible attack vector
                        has_line_fold = true;
                    }
                }
            } else {
                break;
            }
            pos += 1;
        } else {
            break;
        }
    }

    // More than one space, tab, or line folding is suspicious
    space_count > 2 || has_tab || has_line_fold
}

/// Check for header injection via embedded newlines
#[inline(always)]
fn check_header_injection(payload: &[u8], start: usize, limit: usize) -> bool {
    // Find the colon first
    let mut pos = start;
    while pos < limit {
        if let Some(&c) = payload.get(pos) {
            if c == b':' {
                pos += 1;
                break;
            }
            pos += 1;
        } else {
            return false;
        }
    }

    // Scan value for embedded \r\n that's not followed by space/tab (not line folding)
    while pos < limit.saturating_sub(2) {
        if let Some(&c) = payload.get(pos) {
            if c == b'\r' {
                if payload.get(pos + 1) == Some(&b'\n') {
                    let next = payload.get(pos + 2);
                    // If not followed by space/tab, and not end of headers, it's injection
                    if next != Some(&b' ') && next != Some(&b'\t') && next != Some(&b'\r') {
                        return true;
                    }
                    // End of headers or line fold - stop scanning this header
                    break;
                }
            }
            pos += 1;
        } else {
            break;
        }
    }

    false
}

// ============================================================================
// HTTP Validation
// ============================================================================

enum HttpValidation {
    Valid(u8),
    InvalidMethod,
    InvalidRequest,
    Suspicious,
    NotHttp,
    RequestSmuggling,
}

#[inline(always)]
fn validate_http_request(payload: &[u8], config: &HttpConfig) -> HttpValidation {
    if payload.len() < 14 {
        return HttpValidation::NotHttp;
    }

    // Parse HTTP method
    let method = match parse_http_method(payload) {
        Some(m) => m,
        None => return HttpValidation::NotHttp,
    };

    // Block TRACE method (XST attack vector)
    if method == HTTP_METHOD_TRACE && config.protection_level >= 1 {
        return HttpValidation::InvalidMethod;
    }

    // Block CONNECT unless explicitly needed
    if method == HTTP_METHOD_CONNECT && config.protection_level >= 2 {
        return HttpValidation::InvalidMethod;
    }

    // Find the space after method
    let method_len = get_method_length(method);
    if method_len >= payload.len() {
        return HttpValidation::InvalidRequest;
    }

    // Check for space after method
    if payload[method_len] != b' ' {
        return HttpValidation::InvalidRequest;
    }

    // Find HTTP version marker
    let mut found_http = false;
    let mut version_pos = 0;

    // Scan for "HTTP/" (limit scan to prevent DoS)
    let scan_limit = core::cmp::min(payload.len(), 256);
    for i in (method_len + 2)..scan_limit.saturating_sub(5) {
        if payload[i] == b'H'
            && i + 5 <= scan_limit
            && payload[i + 1] == b'T'
            && payload[i + 2] == b'T'
            && payload[i + 3] == b'P'
            && payload[i + 4] == b'/'
        {
            found_http = true;
            version_pos = i + 5;
            break;
        }
    }

    if !found_http {
        return HttpValidation::InvalidRequest;
    }

    // Validate HTTP version (1.0, 1.1, or 2)
    if version_pos + 3 > payload.len() {
        return HttpValidation::InvalidRequest;
    }

    let version_valid = match (
        payload[version_pos],
        payload.get(version_pos + 1),
        payload.get(version_pos + 2),
    ) {
        (b'1', Some(b'.'), Some(b'0' | b'1')) => true,
        (b'2', Some(b'.'), Some(b'0')) => true,
        (b'2', _, _) => true, // HTTP/2
        _ => false,
    };

    if !version_valid {
        return HttpValidation::InvalidRequest;
    }

    // Check for suspicious patterns in the path
    // Path starts after method + space
    let path_start = method_len + 1;
    if check_suspicious_path(&payload[path_start..]) {
        return HttpValidation::Suspicious;
    }

    // HTTP Request Smuggling Detection (for protection level >= 2)
    if config.protection_level >= 2 {
        let smuggling_result = check_request_smuggling(payload);

        if smuggling_result.smuggling_detected {
            // At level 2, flag as suspicious but allow
            // At level 3, block entirely
            if config.protection_level >= 3 {
                return HttpValidation::RequestSmuggling;
            }
            return HttpValidation::Suspicious;
        }
    }

    HttpValidation::Valid(method)
}

#[inline(always)]
fn parse_http_method(payload: &[u8]) -> Option<u8> {
    if payload.len() < 3 {
        return None;
    }

    // Check common methods
    match payload[0] {
        b'G' => {
            if payload.len() >= 3 && payload[1] == b'E' && payload[2] == b'T' {
                return Some(HTTP_METHOD_GET);
            }
        }
        b'P' => {
            if payload.len() >= 4 {
                if payload[1] == b'O' && payload[2] == b'S' && payload[3] == b'T' {
                    return Some(HTTP_METHOD_POST);
                }
                if payload[1] == b'U' && payload[2] == b'T' {
                    return Some(HTTP_METHOD_PUT);
                }
                if payload.len() >= 5
                    && payload[1] == b'A'
                    && payload[2] == b'T'
                    && payload[3] == b'C'
                    && payload[4] == b'H'
                {
                    return Some(HTTP_METHOD_PATCH);
                }
            }
        }
        b'D' => {
            if payload.len() >= 6
                && payload[1] == b'E'
                && payload[2] == b'L'
                && payload[3] == b'E'
                && payload[4] == b'T'
                && payload[5] == b'E'
            {
                return Some(HTTP_METHOD_DELETE);
            }
        }
        b'H' => {
            if payload.len() >= 4 && payload[1] == b'E' && payload[2] == b'A' && payload[3] == b'D'
            {
                return Some(HTTP_METHOD_HEAD);
            }
        }
        b'O' => {
            if payload.len() >= 7
                && payload[1] == b'P'
                && payload[2] == b'T'
                && payload[3] == b'I'
                && payload[4] == b'O'
                && payload[5] == b'N'
                && payload[6] == b'S'
            {
                return Some(HTTP_METHOD_OPTIONS);
            }
        }
        b'C' => {
            if payload.len() >= 7
                && payload[1] == b'O'
                && payload[2] == b'N'
                && payload[3] == b'N'
                && payload[4] == b'E'
                && payload[5] == b'C'
                && payload[6] == b'T'
            {
                return Some(HTTP_METHOD_CONNECT);
            }
        }
        b'T' => {
            if payload.len() >= 5
                && payload[1] == b'R'
                && payload[2] == b'A'
                && payload[3] == b'C'
                && payload[4] == b'E'
            {
                return Some(HTTP_METHOD_TRACE);
            }
        }
        _ => {}
    }

    None
}

#[inline(always)]
fn get_method_length(method: u8) -> usize {
    match method {
        HTTP_METHOD_GET => 3,
        HTTP_METHOD_PUT => 3,
        HTTP_METHOD_POST => 4,
        HTTP_METHOD_HEAD => 4,
        HTTP_METHOD_PATCH => 5,
        HTTP_METHOD_TRACE => 5,
        HTTP_METHOD_DELETE => 6,
        HTTP_METHOD_OPTIONS => 7,
        HTTP_METHOD_CONNECT => 7,
        _ => 3,
    }
}

#[inline(always)]
fn check_suspicious_path(path: &[u8]) -> bool {
    let scan_limit = core::cmp::min(path.len(), 128);

    // Check for directory traversal
    for i in 0..scan_limit.saturating_sub(2) {
        if path[i] == b'.' && path.get(i + 1) == Some(&b'.') {
            // Found ".." - potential directory traversal
            return true;
        }
    }

    // Check for null byte injection
    for i in 0..scan_limit {
        if path[i] == 0 {
            return true;
        }
    }

    // Check for common attack patterns
    // %00 (null byte URL encoded)
    for i in 0..scan_limit.saturating_sub(2) {
        if path[i] == b'%' && path.get(i + 1) == Some(&b'0') && path.get(i + 2) == Some(&b'0') {
            return true;
        }
    }

    false
}

#[inline(always)]
fn is_http2_preface(payload: &[u8]) -> bool {
    if payload.len() < 24 {
        return false;
    }

    for i in 0..24 {
        if payload[i] != HTTP2_PREFACE[i] {
            return false;
        }
    }
    true
}

// ============================================================================
// Rate Limiting
// ============================================================================

#[inline(always)]
fn check_rate_limit_v4(src_ip: u32, config: &HttpConfig) -> bool {
    let now = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
    let window_size = if config.window_size_ns != 0 {
        config.window_size_ns
    } else {
        DEFAULT_WINDOW_SIZE_NS
    };
    let max_requests = if config.max_requests_per_window != 0 {
        config.max_requests_per_window as u64
    } else {
        DEFAULT_MAX_REQUESTS_PER_WINDOW as u64
    };

    if let Some(rate) = unsafe { HTTP_RATE_LIMITS.get_ptr_mut(&src_ip) } {
        let rate = unsafe { &mut *rate };

        // Check if in new window
        if now.saturating_sub(rate.window_start) > window_size {
            // New window
            rate.window_start = now;
            rate.requests = 1;
            return true;
        }

        rate.requests += 1;

        if rate.requests > max_requests {
            // Rate exceeded - consider blocking
            rate.errors += 1;
            if rate.errors > 10 {
                // Persistent rate limit violation - block
                rate.blocked_until = now + config.block_duration_ns;
            }
            return false;
        }

        true
    } else {
        // First request from this IP
        let rate = HttpRateLimit {
            requests: 1,
            window_start: now,
            bytes: 0,
            errors: 0,
            slow_requests: 0,
            blocked_until: 0,
        };
        let _ = HTTP_RATE_LIMITS.insert(&src_ip, &rate, 0);
        true
    }
}

#[inline(always)]
fn is_ip_blocked_v4(src_ip: u32) -> bool {
    if let Some(rate) = unsafe { HTTP_RATE_LIMITS.get(&src_ip) } {
        let now = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
        rate.blocked_until > now
    } else {
        false
    }
}

#[inline(always)]
fn is_ip_blocked_v6(src_ip: &[u8; 16]) -> bool {
    if let Some(rate) = unsafe { HTTP_RATE_LIMITS_V6.get(src_ip) } {
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

    if let Some(rate) = unsafe { HTTP_RATE_LIMITS.get_ptr_mut(&src_ip) } {
        let rate = unsafe { &mut *rate };
        rate.blocked_until = block_until;
    } else {
        let rate = HttpRateLimit {
            requests: 0,
            window_start: now,
            bytes: 0,
            errors: 1,
            slow_requests: 0,
            blocked_until: block_until,
        };
        let _ = HTTP_RATE_LIMITS.insert(&src_ip, &rate, 0);
    }
}

// ============================================================================
// Connection Tracking
// ============================================================================

#[inline(always)]
fn make_connection_key(src_ip: u32, src_port: u16, dst_port: u16) -> u64 {
    ((src_ip as u64) << 32) | ((src_port as u64) << 16) | (dst_port as u64)
}

#[inline(always)]
fn get_or_create_connection(conn_key: u64, now: u64) -> HttpConnectionState {
    if let Some(state) = unsafe { HTTP_CONNECTIONS.get(&conn_key) } {
        *state
    } else {
        let state = HttpConnectionState {
            state: 1, // Request started
            http_version: 0,
            method: 0,
            flags: 0,
            request_start: now,
            last_seen: now,
            bytes_received: 0,
            headers_bytes: 0,
            request_count: 0,
            content_length: 0,
            body_bytes_received: 0,
            body_start: 0,
        };
        let _ = HTTP_CONNECTIONS.insert(&conn_key, &state, 0);
        state
    }
}

// ============================================================================
// Configuration
// ============================================================================

#[inline(always)]
fn get_config() -> HttpConfig {
    if let Some(config) = unsafe { HTTP_CONFIG.get_ptr(0) } {
        unsafe { *config }
    } else {
        HttpConfig {
            enabled: 1,
            http_port: DEFAULT_HTTP_PORT,
            https_port: DEFAULT_HTTPS_PORT,
            max_requests_per_window: DEFAULT_MAX_REQUESTS_PER_WINDOW,
            window_size_ns: DEFAULT_WINDOW_SIZE_NS,
            max_header_size: DEFAULT_MAX_HEADER_SIZE,
            max_header_time_ns: DEFAULT_MAX_HEADER_TIME_NS,
            max_body_size: DEFAULT_MAX_BODY_SIZE,
            block_duration_ns: DEFAULT_BLOCK_DURATION_NS,
            protection_level: 2,
            max_body_time_ns: DEFAULT_MAX_BODY_TIME_NS,
            min_body_rate_bps: DEFAULT_MIN_BODY_RATE_BPS,
            http2_max_rst_per_window: DEFAULT_HTTP2_MAX_RST_PER_WINDOW,
            http2_max_control_frames_per_window: DEFAULT_HTTP2_MAX_CONTROL_FRAMES_PER_WINDOW,
            http2_max_streams: DEFAULT_HTTP2_MAX_STREAMS,
            http2_rst_window_ns: DEFAULT_HTTP2_RST_WINDOW_NS,
        }
    }
}

// ============================================================================
// Statistics
// ============================================================================

#[inline(always)]
fn update_stats_total() {
    if let Some(stats) = unsafe { HTTP_STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).total_requests += 1;
        }
    }
}

#[inline(always)]
fn update_stats_passed() {
    if let Some(stats) = unsafe { HTTP_STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).passed_requests += 1;
        }
    }
}

#[inline(always)]
fn update_stats_invalid_method() {
    if let Some(stats) = unsafe { HTTP_STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).dropped_invalid_method += 1;
        }
    }
}

#[inline(always)]
fn update_stats_rate_limited() {
    if let Some(stats) = unsafe { HTTP_STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).dropped_rate_limited += 1;
        }
    }
}

#[inline(always)]
fn update_stats_slow_loris() {
    if let Some(stats) = unsafe { HTTP_STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).dropped_slow_loris += 1;
        }
    }
}

#[inline(always)]
fn update_stats_invalid() {
    if let Some(stats) = unsafe { HTTP_STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).dropped_invalid_request += 1;
        }
    }
}

#[inline(always)]
fn update_stats_blocked() {
    if let Some(stats) = unsafe { HTTP_STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).dropped_blocked_ip += 1;
        }
    }
}

#[inline(always)]
fn update_stats_http2() {
    if let Some(stats) = unsafe { HTTP_STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).http2_requests += 1;
        }
    }
}

#[inline(always)]
fn update_stats_slow_post() {
    if let Some(stats) = unsafe { HTTP_STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).dropped_slow_post += 1;
        }
    }
}

#[inline(always)]
fn update_stats_http2_rapid_reset() {
    if let Some(stats) = unsafe { HTTP_STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).dropped_http2_rapid_reset += 1;
        }
    }
}

#[inline(always)]
fn update_stats_http2_control_flood() {
    if let Some(stats) = unsafe { HTTP_STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).dropped_http2_control_flood += 1;
        }
    }
}

#[inline(always)]
fn update_stats_http2_rst_stream() {
    if let Some(stats) = unsafe { HTTP_STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).http2_rst_stream_frames += 1;
        }
    }
}

#[inline(always)]
fn update_stats_http2_headers() {
    if let Some(stats) = unsafe { HTTP_STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).http2_headers_frames += 1;
        }
    }
}

#[inline(always)]
fn update_stats_http2_data() {
    if let Some(stats) = unsafe { HTTP_STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).http2_data_frames += 1;
        }
    }
}

#[inline(always)]
fn update_stats_request_smuggling() {
    if let Some(stats) = unsafe { HTTP_STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).dropped_request_smuggling += 1;
        }
    }
}

#[inline(always)]
fn update_stats_header_injection() {
    if let Some(stats) = unsafe { HTTP_STATS.get_ptr_mut(0) } {
        unsafe {
            (*stats).dropped_header_injection += 1;
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
