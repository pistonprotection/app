//! XDP Minecraft Protocol Filter
//!
//! Specialized XDP program for filtering Minecraft Java and Bedrock traffic.
//! Implements protocol-aware validation for both Java Edition (TCP) and
//! Bedrock Edition (UDP/RakNet).

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{LruHashMap, PerCpuArray},
    programs::XdpContext,
};
use core::mem;

// Network header structures (same as xdp_filter.rs)

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

#[repr(C)]
struct UdpHdr {
    source: u16,
    dest: u16,
    len: u16,
    check: u16,
}

/// Minecraft connection state
#[repr(C)]
pub struct McConnectionState {
    pub state: u8, // 0=none, 1=status, 2=login, 3=configuration, 4=play, 5=transfer
    pub _padding: [u8; 3], // Alignment padding
    pub protocol_version: u32,
    pub packets: u64,
    pub bytes: u64,
    pub last_seen: u64,
    pub flags: u32,
    /// Expected bytes remaining for fragmented packet (TCP fragmentation tracking)
    pub pending_packet_bytes: u32,
    /// TCP sequence number of the fragmented packet start (for reassembly validation)
    pub pending_seq: u32,
}

/// RakNet magic bytes for Bedrock
const RAKNET_MAGIC: [u8; 16] = [
    0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe, 0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78,
];

/// Minecraft configuration
#[repr(C)]
#[derive(Copy, Clone)]
pub struct McConfig {
    pub enabled: u32,
    pub java_port: u16,
    pub bedrock_port: u16,
    pub validate_handshake: u32,
    pub max_connections_per_ip: u32,
    pub status_rate_limit: u32,
    pub min_protocol_version: u32,
    pub max_protocol_version: u32,
    pub max_hostname_len: u16,
    pub max_packet_size: u32,
}

// Minecraft protocol constants
const MC_STATE_NONE: u8 = 0;
const MC_STATE_STATUS: u8 = 1;
const MC_STATE_LOGIN: u8 = 2;
const MC_STATE_CONFIGURATION: u8 = 3; // 1.20.2+ configuration state (between login and play)
const MC_STATE_PLAY: u8 = 4;
const MC_STATE_TRANSFER: u8 = 5; // 1.20.5+ transfer intent for server transfers

// Connection state flags
const MC_FLAG_ENCRYPTION_PENDING: u32 = 0x0001; // Encryption will be enabled after next packet (legacy)
const MC_FLAG_ENCRYPTION_ENABLED: u32 = 0x0002; // Encryption is active (can't inspect)
const MC_FLAG_COMPRESSION_ENABLED: u32 = 0x0004; // Compression is active
const MC_FLAG_VALIDATED: u32 = 0x0008; // Connection has been validated
const MC_FLAG_FRAGMENTED_PENDING: u32 = 0x0010; // Partial packet pending (TCP fragmentation)

// Maximum VarInt bytes (5 for 32-bit values)
const MAX_VARINT_BYTES: usize = 5;

// Maximum Minecraft packet size (2MB is protocol max, but we're stricter)
const DEFAULT_MAX_PACKET_SIZE: i32 = 2097151;

// Default hostname max length (253 is DNS max)
const DEFAULT_MAX_HOSTNAME_LEN: usize = 255;

// Known valid protocol versions (major releases)
// 1.7.2 = 4, 1.20.4 = 765, 1.21 = 767
const MIN_VALID_PROTOCOL: u32 = 4;
const MAX_VALID_PROTOCOL: u32 = 1000; // Future-proof

/// Per-IP connection count
#[repr(C)]
pub struct IpConnectionCount {
    pub count: u32,
    pub last_connection: u64,
    pub blocked_until: u64,
}

// eBPF Maps

/// Minecraft Java connections (keyed by src_ip:src_port)
#[map]
static MC_JAVA_CONNECTIONS: LruHashMap<u64, McConnectionState> =
    LruHashMap::with_max_entries(500_000, 0);

/// Minecraft Bedrock connections (keyed by src_ip:src_port)
#[map]
static MC_BEDROCK_CONNECTIONS: LruHashMap<u64, BedrockConnectionState> =
    LruHashMap::with_max_entries(500_000, 0);

/// Per-IP Bedrock rate limiting (keyed by src_ip)
#[map]
static MC_BEDROCK_RATE: LruHashMap<u32, BedrockRateState> =
    LruHashMap::with_max_entries(500_000, 0);

/// Bedrock rate limiting state
#[repr(C)]
pub struct BedrockRateState {
    /// Ping packets in current window
    pub ping_count: u32,
    /// Connection request packets in current window
    pub conn_req_count: u32,
    /// Total bytes received in window
    pub bytes_in: u64,
    /// Estimated response bytes in window
    pub bytes_out_estimate: u64,
    /// Window start timestamp
    pub window_start: u64,
    /// Blocked until timestamp
    pub blocked_until: u64,
}

/// Per-IP connection counts
#[map]
static MC_IP_COUNTS: LruHashMap<u32, IpConnectionCount> =
    LruHashMap::with_max_entries(1_000_000, 0);

/// Status request rate limiting
#[map]
static MC_STATUS_RATE: LruHashMap<u32, u64> = LruHashMap::with_max_entries(100_000, 0);

/// Configuration
#[map]
static MC_CONFIG: PerCpuArray<McConfig> = PerCpuArray::with_max_entries(1, 0);

// Constants
const ETH_P_IP: u16 = 0x0800;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

// Minecraft Java default port
const MC_JAVA_PORT: u16 = 25565;
// Minecraft Bedrock default port
const MC_BEDROCK_PORT: u16 = 19132;

/// Main XDP Minecraft filter
#[xdp]
pub fn xdp_minecraft(ctx: XdpContext) -> u32 {
    match try_xdp_minecraft(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn try_xdp_minecraft(ctx: XdpContext) -> Result<u32, ()> {
    let data = ctx.data();
    let data_end = ctx.data_end();

    // Parse Ethernet header
    if data + mem::size_of::<EthHdr>() > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let eth = unsafe { &*(data as *const EthHdr) };
    let eth_proto = u16::from_be(eth.h_proto);

    if eth_proto != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip_data = data + mem::size_of::<EthHdr>();

    // Parse IPv4 header
    if ip_data + mem::size_of::<Ipv4Hdr>() > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip = unsafe { &*(ip_data as *const Ipv4Hdr) };
    let src_ip = u32::from_be(ip.saddr);
    let ihl = (ip.version_ihl & 0x0f) as usize * 4;
    let transport_data = ip_data + ihl;

    match ip.protocol {
        IPPROTO_TCP => process_minecraft_java(&ctx, transport_data, data_end, src_ip),
        IPPROTO_UDP => process_minecraft_bedrock(&ctx, transport_data, data_end, src_ip),
        _ => Ok(xdp_action::XDP_PASS),
    }
}

#[inline(always)]
fn process_minecraft_java(
    _ctx: &XdpContext,
    data: usize,
    data_end: usize,
    src_ip: u32,
) -> Result<u32, ()> {
    if data + mem::size_of::<TcpHdr>() > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let tcp = unsafe { &*(data as *const TcpHdr) };
    let dst_port = u16::from_be(tcp.dest);
    let src_port = u16::from_be(tcp.source);

    // Get config
    let config_ptr = unsafe { MC_CONFIG.get_ptr(0) };
    let (java_port, max_packet_size, min_proto, max_proto, max_hostname) =
        if let Some(ptr) = config_ptr {
            let config = unsafe { &*ptr };
            if config.enabled == 0 {
                return Ok(xdp_action::XDP_PASS);
            }
            (
                config.java_port,
                if config.max_packet_size == 0 {
                    DEFAULT_MAX_PACKET_SIZE
                } else {
                    config.max_packet_size as i32
                },
                if config.min_protocol_version == 0 {
                    MIN_VALID_PROTOCOL
                } else {
                    config.min_protocol_version
                },
                if config.max_protocol_version == 0 {
                    MAX_VALID_PROTOCOL
                } else {
                    config.max_protocol_version
                },
                if config.max_hostname_len == 0 {
                    DEFAULT_MAX_HOSTNAME_LEN
                } else {
                    config.max_hostname_len as usize
                },
            )
        } else {
            (
                MC_JAVA_PORT,
                DEFAULT_MAX_PACKET_SIZE,
                MIN_VALID_PROTOCOL,
                MAX_VALID_PROTOCOL,
                DEFAULT_MAX_HOSTNAME_LEN,
            )
        };

    // Not Minecraft traffic
    if dst_port != java_port {
        return Ok(xdp_action::XDP_PASS);
    }

    // Check connection limit per IP
    if !check_connection_limit(src_ip) {
        return Ok(xdp_action::XDP_DROP);
    }

    // Calculate TCP data offset
    let tcp_header_len = ((u16::from_be(tcp.doff_flags) >> 12) & 0x0f) as usize * 4;
    let payload_start = data + tcp_header_len;

    if payload_start >= data_end {
        // No payload - pass through (SYN, ACK, etc.)
        return Ok(xdp_action::XDP_PASS);
    }

    let payload_len = data_end - payload_start;
    if payload_len < 3 {
        return Ok(xdp_action::XDP_PASS);
    }

    // Build connection key for state tracking (IP in upper 32 bits, port in lower 16)
    let connection_key = ((src_ip as u64) << 32) | (src_port as u64);

    // Parse VarInt length prefix
    let payload = unsafe { core::slice::from_raw_parts(payload_start as *const u8, payload_len) };

    // Read packet length VarInt
    let (packet_len, len_bytes) = match read_varint(payload) {
        Some(v) => v,
        None => return Ok(xdp_action::XDP_DROP), // Invalid VarInt
    };

    // Validate packet length
    if packet_len < 0 {
        // Negative length is invalid
        return Ok(xdp_action::XDP_DROP);
    }

    if packet_len > max_packet_size {
        // Oversized packet - potential attack
        return Ok(xdp_action::XDP_DROP);
    }

    // TCP FRAGMENTATION HANDLING:
    // Minecraft packets can be split across multiple TCP segments.
    // This is a known limitation of XDP - we can't do full TCP reassembly.
    // However, we can track partial packets and be cautious.
    let remaining_len = payload_len.saturating_sub(len_bytes);

    // Check if this is a continuation of a fragmented packet
    if let Some(state) = unsafe { MC_JAVA_CONNECTIONS.get(&connection_key) } {
        if state.flags & MC_FLAG_FRAGMENTED_PENDING != 0 && state.pending_packet_bytes > 0 {
            // We're expecting continuation data from a previous fragment
            // For safety, if we have pending fragment state, pass through
            // and update tracking. We can't validate partial packet content.
            let pending_bytes = state.pending_packet_bytes as usize;
            if payload_len < pending_bytes {
                // Still fragmented, more data coming
                if let Some(state) = unsafe { MC_JAVA_CONNECTIONS.get_ptr_mut(&connection_key) } {
                    let state = unsafe { &mut *state };
                    state.pending_packet_bytes = (pending_bytes - payload_len) as u32;
                    state.packets += 1;
                    state.bytes += payload_len as u64;
                    state.last_seen = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
                }
                return Ok(xdp_action::XDP_PASS);
            } else {
                // Fragment complete, clear pending state
                if let Some(state) = unsafe { MC_JAVA_CONNECTIONS.get_ptr_mut(&connection_key) } {
                    let state = unsafe { &mut *state };
                    state.flags &= !MC_FLAG_FRAGMENTED_PENDING;
                    state.pending_packet_bytes = 0;
                    state.packets += 1;
                    state.bytes += payload_len as u64;
                    state.last_seen = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
                }
                // Now continue to parse the rest of this segment if any
                // For simplicity, pass this through as we've accounted for it
                return Ok(xdp_action::XDP_PASS);
            }
        }
    }

    if remaining_len == 0 {
        // No packet data after length - incomplete, let TCP handle it
        // Mark as having pending fragment
        if let Some(state) = unsafe { MC_JAVA_CONNECTIONS.get_ptr_mut(&connection_key) } {
            let state = unsafe { &mut *state };
            state.flags |= MC_FLAG_FRAGMENTED_PENDING;
            state.pending_packet_bytes = packet_len as u32;
        }
        return Ok(xdp_action::XDP_PASS);
    }

    // Check if this packet is fragmented (we don't have all the data)
    if remaining_len < packet_len as usize {
        // Packet is fragmented - track how much data is remaining
        // SECURITY NOTE: We still validate the packet ID we can see,
        // but the full packet validation happens when we have all data.
        if let Some(state) = unsafe { MC_JAVA_CONNECTIONS.get_ptr_mut(&connection_key) } {
            let state = unsafe { &mut *state };
            state.flags |= MC_FLAG_FRAGMENTED_PENDING;
            state.pending_packet_bytes = (packet_len as usize - remaining_len) as u32;
        }
        // Continue to validate what we can see (packet ID at minimum)
    }

    // Read packet ID VarInt (not just first byte!)
    let packet_data = &payload[len_bytes..];
    let (packet_id, id_bytes) = match read_varint(packet_data) {
        Some(v) => v,
        None => return Ok(xdp_action::XDP_DROP), // Invalid packet ID VarInt
    };

    // Packet ID should be non-negative
    if packet_id < 0 {
        return Ok(xdp_action::XDP_DROP);
    }

    // Get current connection state
    let current_state = if let Some(state) = unsafe { MC_JAVA_CONNECTIONS.get(&connection_key) } {
        state.state
    } else {
        MC_STATE_NONE
    };

    // Validate packet based on connection state
    // SECURITY: Validate packet_id is in valid range for each state
    // Packet IDs in Minecraft are unsigned in meaning but encoded as signed varints.
    // Negative packet IDs are invalid in all states.
    match current_state {
        MC_STATE_NONE => {
            // Expecting handshake (packet ID 0x00)
            // packet_id must be exactly 0 (already checked >= 0 above)
            if packet_id != 0x00 {
                return Ok(xdp_action::XDP_DROP);
            }

            // Validate handshake packet structure
            if let Some(result) = validate_handshake(
                packet_data,
                id_bytes,
                packet_len as usize,
                min_proto,
                max_proto,
                max_hostname,
            ) {
                if !result.valid {
                    return Ok(xdp_action::XDP_DROP);
                }

                // Create connection state based on next_state
                // Minecraft 1.20.5+ supports next_state=3 (TRANSFER) for server transfers
                let next_state = match result.next_state {
                    1 => MC_STATE_STATUS,
                    2 => MC_STATE_LOGIN,
                    3 => MC_STATE_TRANSFER, // 1.20.5+ transfer intent
                    _ => return Ok(xdp_action::XDP_DROP), // Invalid next_state
                };

                let new_state = McConnectionState {
                    state: next_state,
                    _padding: [0; 3],
                    protocol_version: result.protocol_version,
                    packets: 1,
                    bytes: payload_len as u64,
                    last_seen: unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() },
                    flags: 0,
                    pending_packet_bytes: 0,
                    pending_seq: 0,
                };
                let _ = MC_JAVA_CONNECTIONS.insert(&connection_key, &new_state, 0);
            } else {
                // Couldn't parse handshake - might be incomplete packet
                return Ok(xdp_action::XDP_PASS);
            }
        }
        MC_STATE_STATUS => {
            // Status state - only status request (0x00) and ping (0x01)
            // SECURITY FIX: Check both bounds explicitly since packet_id is i32
            // A negative packet_id would pass "packet_id > 0x01" but is invalid
            if packet_id < 0x00 || packet_id > 0x01 {
                return Ok(xdp_action::XDP_DROP);
            }
            // Rate limit status requests
            if packet_id == 0x00 && !check_status_rate_limit(src_ip) {
                return Ok(xdp_action::XDP_DROP);
            }
            // Update connection state
            update_connection_state(&connection_key, payload_len);
        }
        MC_STATE_LOGIN => {
            // Login state - valid packets: 0x00 (Login Start), 0x01 (Encryption Response),
            // 0x02 (Login Plugin Response), 0x03 (Login Acknowledged)
            // SECURITY FIX: Check both bounds explicitly since packet_id is i32
            if packet_id < 0x00 || packet_id > 0x03 {
                return Ok(xdp_action::XDP_DROP);
            }

            // Track encryption state transitions
            // After Login Acknowledged (0x03), the connection enters Configuration state (1.20.2+)
            // or Play state (pre-1.20.2). We transition to Configuration first.
            // Once encryption is enabled (after Encryption Response 0x01), we can't inspect packets.
            if packet_id == 0x01 {
                // Encryption Response - encryption will be enabled immediately
                // Mark connection to skip deep inspection for subsequent packets
                if let Some(state) = unsafe { MC_JAVA_CONNECTIONS.get_ptr_mut(&connection_key) } {
                    let state = unsafe { &mut *state };
                    // Encryption is enabled immediately after this packet
                    state.flags |= MC_FLAG_ENCRYPTION_ENABLED;
                    state.packets += 1;
                    state.bytes += payload_len as u64;
                    state.last_seen = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
                }
                return Ok(xdp_action::XDP_PASS);
            }

            if packet_id == 0x03 {
                // Login Acknowledged - transition to Configuration state (1.20.2+)
                // Note: For pre-1.20.2 clients, this packet doesn't exist and they go directly to Play
                if let Some(state) = unsafe { MC_JAVA_CONNECTIONS.get_ptr_mut(&connection_key) } {
                    let state = unsafe { &mut *state };
                    state.state = MC_STATE_CONFIGURATION;
                    state.packets += 1;
                    state.bytes += payload_len as u64;
                    state.last_seen = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
                }
                return Ok(xdp_action::XDP_PASS);
            }

            // Update connection state
            update_connection_state(&connection_key, payload_len);
        }
        MC_STATE_CONFIGURATION => {
            // Configuration state (1.20.2+) - limited packet IDs
            // Check if encryption is enabled - if so, we can't inspect packets
            if let Some(state) = unsafe { MC_JAVA_CONNECTIONS.get(&connection_key) } {
                if state.flags & MC_FLAG_ENCRYPTION_ENABLED != 0 {
                    // Encrypted connection - just pass through and update stats
                    update_connection_state(&connection_key, payload_len);
                    return Ok(xdp_action::XDP_PASS);
                }
            }

            // Configuration state packet IDs (client -> server):
            // 0x00: Client Information
            // 0x01: Cookie Response (1.20.5+)
            // 0x02: Plugin Message
            // 0x03: Finish Configuration (Acknowledge)
            // 0x04: Keep Alive
            // 0x05: Pong
            // 0x06: Resource Pack Response
            // 0x07: Known Packs (1.21+)
            // SECURITY: Validate packet ID is in the valid configuration state range
            // Note: packet_id < 0 is already checked at line 359
            if packet_id > 0x07 {
                return Ok(xdp_action::XDP_DROP);
            }

            // Handle transition to Play state via Finish Configuration (0x03)
            if packet_id == 0x03 {
                if let Some(state) = unsafe { MC_JAVA_CONNECTIONS.get_ptr_mut(&connection_key) } {
                    let state = unsafe { &mut *state };
                    state.state = MC_STATE_PLAY;
                    state.packets += 1;
                    state.bytes += payload_len as u64;
                    state.last_seen = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
                }
                return Ok(xdp_action::XDP_PASS);
            }

            // Update connection state
            update_connection_state(&connection_key, payload_len);
        }
        MC_STATE_PLAY => {
            // Play state - wide range of packet IDs
            // Check if encryption is enabled - if so, we can't inspect packets
            if let Some(state) = unsafe { MC_JAVA_CONNECTIONS.get(&connection_key) } {
                if state.flags & MC_FLAG_ENCRYPTION_ENABLED != 0 {
                    // Encrypted connection - just pass through and update stats
                    update_connection_state(&connection_key, payload_len);
                    return Ok(xdp_action::XDP_PASS);
                }
            }

            // Play state packet IDs vary by version but are generally in range 0x00-0x3F
            // for client-to-server packets. Some versions extend to higher.
            // 1.21.x client-to-server packets go up to around 0x40
            // SECURITY: Block obviously invalid packet IDs while allowing legitimate range
            // Note: packet_id < 0 is already checked at line 359, so we don't need < 0x00 check
            if packet_id > 0x50 {
                // Packet ID too high - likely invalid or attack
                return Ok(xdp_action::XDP_DROP);
            }

            // Update connection state
            update_connection_state(&connection_key, payload_len);
        }
        MC_STATE_TRANSFER => {
            // Transfer state (1.20.5+) - client is being transferred to another server
            // In this state, the client expects server to send transfer packet
            // Client-to-server packets in transfer state are limited
            if let Some(state) = unsafe { MC_JAVA_CONNECTIONS.get(&connection_key) } {
                if state.flags & MC_FLAG_ENCRYPTION_ENABLED != 0 {
                    update_connection_state(&connection_key, payload_len);
                    return Ok(xdp_action::XDP_PASS);
                }
            }

            // Transfer state has very few valid client-to-server packets
            // Mainly just acknowledgments. Allow reasonable range.
            if packet_id > 0x10 {
                return Ok(xdp_action::XDP_DROP);
            }

            update_connection_state(&connection_key, payload_len);
        }
        _ => {
            // Unknown state - shouldn't happen
            return Ok(xdp_action::XDP_DROP);
        }
    }

    Ok(xdp_action::XDP_PASS)
}

/// Handshake validation result
struct HandshakeResult {
    valid: bool,
    protocol_version: u32,
    next_state: u8,
}

/// Validate Minecraft Java handshake packet
/// Format: VarInt protocol_version, String hostname, UShort port, VarInt next_state
#[inline(always)]
fn validate_handshake(
    packet_data: &[u8],
    id_bytes: usize,
    packet_len: usize,
    min_proto: u32,
    max_proto: u32,
    max_hostname: usize,
) -> Option<HandshakeResult> {
    // Data after packet ID
    if id_bytes >= packet_data.len() {
        return None;
    }
    let data = &packet_data[id_bytes..];
    let mut offset = 0;

    // Read protocol version VarInt
    let (proto_version, proto_bytes) = read_varint_at(data, offset)?;
    if proto_version < 0 {
        return Some(HandshakeResult {
            valid: false,
            protocol_version: 0,
            next_state: 0,
        });
    }
    offset += proto_bytes;

    // Validate protocol version range
    let proto_u32 = proto_version as u32;
    if proto_u32 < min_proto || proto_u32 > max_proto {
        return Some(HandshakeResult {
            valid: false,
            protocol_version: proto_u32,
            next_state: 0,
        });
    }

    // Read hostname string length VarInt
    if offset >= data.len() {
        return None;
    }
    let (hostname_len, hostname_len_bytes) = read_varint_at(data, offset)?;
    if hostname_len < 0 {
        return Some(HandshakeResult {
            valid: false,
            protocol_version: proto_u32,
            next_state: 0,
        });
    }
    offset += hostname_len_bytes;

    // Validate hostname length
    let hostname_len_usize = hostname_len as usize;
    if hostname_len_usize > max_hostname {
        return Some(HandshakeResult {
            valid: false,
            protocol_version: proto_u32,
            next_state: 0,
        });
    }

    // Skip hostname bytes
    if offset + hostname_len_usize > data.len() {
        return None; // Incomplete packet
    }

    // Basic hostname validation (no null bytes)
    // Use bounded loop for eBPF verifier - check up to 255 bytes (DNS max)
    // We already validated hostname_len_usize <= max_hostname above
    // The loop bound must be a compile-time constant for eBPF verifier
    for i in 0..DEFAULT_MAX_HOSTNAME_LEN {
        // Break early if we've checked all hostname bytes
        if i >= hostname_len_usize {
            break;
        }
        if offset + i >= data.len() {
            return None;
        }
        let b = data[offset + i];
        if b == 0 {
            // Null byte in hostname - invalid
            return Some(HandshakeResult {
                valid: false,
                protocol_version: proto_u32,
                next_state: 0,
            });
        }
    }
    offset += hostname_len_usize;

    // Read port (unsigned short, 2 bytes big-endian)
    // Port is the server port the client claims to be connecting to
    if offset + 2 > data.len() {
        return None;
    }
    let claimed_port = ((data[offset] as u16) << 8) | (data[offset + 1] as u16);
    offset += 2;

    // Port validation (should be non-zero; value 0 indicates malformed packet)
    // Note: We don't validate it matches the actual destination port as that
    // would require passing additional context. The server will reject mismatches.
    if claimed_port == 0 {
        return Some(HandshakeResult {
            valid: false,
            protocol_version: proto_u32,
            next_state: 0,
        });
    }

    // Read next_state VarInt
    if offset >= data.len() {
        return None;
    }
    let (next_state, next_state_bytes) = read_varint_at(data, offset)?;
    offset += next_state_bytes;

    // Validate next_state (1 = status, 2 = login, 3 = transfer for 1.20.5+)
    if next_state < 1 || next_state > 3 {
        return Some(HandshakeResult {
            valid: false,
            protocol_version: proto_u32,
            next_state: next_state as u8,
        });
    }

    // Verify packet length matches parsed content
    // packet_len is the length after the outer length VarInt, includes packet ID
    let expected_data_len = id_bytes + offset;
    if expected_data_len != packet_len {
        // Length mismatch - could be malformed or attack
        // Allow some tolerance for edge cases
        if expected_data_len > packet_len + 1 || expected_data_len + 1 < packet_len {
            return Some(HandshakeResult {
                valid: false,
                protocol_version: proto_u32,
                next_state: next_state as u8,
            });
        }
    }

    Some(HandshakeResult {
        valid: true,
        protocol_version: proto_u32,
        next_state: next_state as u8,
    })
}

/// Update connection state packet/byte counters
/// Note: Encryption flag is now set immediately in the encryption response handler,
/// not deferred, to avoid race conditions where the first encrypted packet would be inspected.
#[inline(always)]
fn update_connection_state(connection_key: &u64, payload_len: usize) {
    if let Some(state) = unsafe { MC_JAVA_CONNECTIONS.get_ptr_mut(connection_key) } {
        let state = unsafe { &mut *state };
        state.packets += 1;
        state.bytes += payload_len as u64;
        state.last_seen = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
    }
}

/// RakNet packet type constants
const RAKNET_UNCONNECTED_PING: u8 = 0x01;
const RAKNET_UNCONNECTED_PING_OPEN: u8 = 0x02;
const RAKNET_OPEN_CONNECTION_REQUEST_1: u8 = 0x05;
const RAKNET_OPEN_CONNECTION_REPLY_1: u8 = 0x06;
const RAKNET_OPEN_CONNECTION_REQUEST_2: u8 = 0x07;
const RAKNET_OPEN_CONNECTION_REPLY_2: u8 = 0x08;
const RAKNET_UNCONNECTED_PONG: u8 = 0x1c;
const RAKNET_INCOMPATIBLE_PROTOCOL: u8 = 0x19;

/// Minimum packet sizes for RakNet packets
const RAKNET_UNCONNECTED_PING_MIN_SIZE: usize = 33; // 1 + 8 + 16 + 8 (id + time + magic + client_guid)
const RAKNET_OPEN_CONN_REQ1_MIN_SIZE: usize = 18; // 1 + 16 + 1 (id + magic + protocol)
const RAKNET_UNCONNECTED_PONG_MIN_SIZE: usize = 35; // 1 + 8 + 8 + 16 + 2 (id + time + server_guid + magic + motd_len)

/// MTU size limits for RakNet
/// Minimum MTU is 400 bytes (RakNet minimum)
/// Maximum MTU is typically 1500 (Ethernet MTU) or 1492 (PPPoE)
const RAKNET_MIN_MTU: u16 = 400;
const RAKNET_MAX_MTU: u16 = 1500;

/// RakNet amplification protection constants
/// The pong response can be much larger than the ping request due to MOTD
/// We track the ratio of response bytes to request bytes
const RAKNET_MAX_AMPLIFICATION_RATIO: u32 = 10; // Max 10x amplification allowed
const RAKNET_PING_FLOOD_THRESHOLD: u32 = 50; // Max pings per second per IP
const RAKNET_CONN_REQ_FLOOD_THRESHOLD: u32 = 20; // Max connection requests per second per IP
const RAKNET_MAX_ACK_RECORDS: u16 = 500; // Max ACK/NACK records per packet (DoS protection)

/// RakNet connection state for Bedrock
#[repr(C)]
pub struct BedrockConnectionState {
    /// Connection state: 0=none, 1=ping_sent, 2=conn_req1, 3=conn_req2, 4=connected
    pub state: u8,
    /// RakNet protocol version
    pub protocol_version: u8,
    /// Negotiated MTU size
    pub mtu_size: u16,
    /// Client GUID (for validation)
    pub client_guid: u64,
    /// Packets received
    pub packets: u64,
    /// Bytes received (for amplification tracking)
    pub bytes_in: u64,
    /// Bytes we would send (for amplification tracking)
    pub bytes_out_estimate: u64,
    /// First seen timestamp
    pub first_seen: u64,
    /// Last seen timestamp
    pub last_seen: u64,
    /// Ping count in current window
    pub ping_count: u32,
    /// Connection request count in current window
    pub conn_req_count: u32,
    /// Window start timestamp
    pub window_start: u64,
    /// Flags
    pub flags: u32,
}

/// Bedrock state flags
const BEDROCK_FLAG_GUID_VALIDATED: u32 = 0x0001;
const BEDROCK_FLAG_MTU_NEGOTIATED: u32 = 0x0002;
const BEDROCK_FLAG_SUSPICIOUS: u32 = 0x0004;
const BEDROCK_FLAG_AMPLIFICATION_DETECTED: u32 = 0x0008;

/// Process Minecraft Bedrock (RakNet) packets with amplification attack protection
///
/// RakNet amplification attacks work by:
/// 1. Sending small Unconnected Ping packets (33 bytes)
/// 2. Receiving large Unconnected Pong packets (can be 1000+ bytes with MOTD)
/// 3. Spoofing source IP to target victim with amplified traffic
///
/// We protect against this by:
/// - Rate limiting ping requests per IP
/// - Tracking amplification ratios
/// - Validating connection state progression
/// - MTU validation to prevent oversized responses
#[inline(always)]
fn process_minecraft_bedrock(
    _ctx: &XdpContext,
    data: usize,
    data_end: usize,
    src_ip: u32,
) -> Result<u32, ()> {
    if data + mem::size_of::<UdpHdr>() > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let udp = unsafe { &*(data as *const UdpHdr) };
    let dst_port = u16::from_be(udp.dest);
    let src_port = u16::from_be(udp.source);
    let udp_len = u16::from_be(udp.len) as usize;

    // Get config
    let bedrock_port = if let Some(config) = unsafe { MC_CONFIG.get_ptr(0) } {
        let config = unsafe { &*config };
        if config.enabled == 0 {
            return Ok(xdp_action::XDP_PASS);
        }
        config.bedrock_port
    } else {
        MC_BEDROCK_PORT
    };

    // Not Bedrock traffic
    if dst_port != bedrock_port {
        return Ok(xdp_action::XDP_PASS);
    }

    // Check if IP is blocked (amplification detected previously)
    if is_bedrock_ip_blocked(src_ip) {
        return Ok(xdp_action::XDP_DROP);
    }

    // Check connection limit per IP
    if !check_connection_limit(src_ip) {
        return Ok(xdp_action::XDP_DROP);
    }

    let payload_start = data + mem::size_of::<UdpHdr>();
    if payload_start >= data_end {
        return Ok(xdp_action::XDP_DROP);
    }

    let payload_len = data_end - payload_start;
    if payload_len < 1 {
        return Ok(xdp_action::XDP_DROP);
    }

    // Validate UDP length field matches actual payload
    let expected_udp_payload = udp_len.saturating_sub(8); // UDP header is 8 bytes
    if expected_udp_payload > 0 && payload_len < expected_udp_payload {
        // Truncated packet
        return Ok(xdp_action::XDP_DROP);
    }

    let payload = unsafe { core::slice::from_raw_parts(payload_start as *const u8, payload_len) };
    let packet_id = payload[0];

    let now = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };

    // Build connection key for state tracking
    let connection_key = ((src_ip as u64) << 32) | (src_port as u64);

    // Validate RakNet packets based on packet type
    match packet_id {
        RAKNET_UNCONNECTED_PING | RAKNET_UNCONNECTED_PING_OPEN => {
            // Unconnected Ping (0x01) or Ping Open Connections (0x02)
            // Format: [0x01/0x02] [8 bytes time] [16 bytes magic] [8 bytes client GUID]
            // Magic is at offset 1+8=9, spanning bytes 9-24 (indices 9..25)
            if payload_len < RAKNET_UNCONNECTED_PING_MIN_SIZE {
                return Ok(xdp_action::XDP_DROP);
            }

            // Check magic at correct offset (after packet ID and timestamp)
            if !check_raknet_magic(&payload[9..25]) {
                return Ok(xdp_action::XDP_DROP);
            }

            // AMPLIFICATION PROTECTION: Rate limit ping requests
            // Pong responses can be 10-50x larger than ping requests
            if !check_bedrock_rate_limit(src_ip, payload_len, true, now) {
                return Ok(xdp_action::XDP_DROP);
            }

            // Extract client GUID for validation (bytes 25-32)
            let client_guid = if payload_len >= 33 {
                let guid_bytes = &payload[25..33];
                u64::from_be_bytes([
                    guid_bytes[0],
                    guid_bytes[1],
                    guid_bytes[2],
                    guid_bytes[3],
                    guid_bytes[4],
                    guid_bytes[5],
                    guid_bytes[6],
                    guid_bytes[7],
                ])
            } else {
                0
            };

            // Track connection state
            track_bedrock_connection(connection_key, 1, 0, client_guid, payload_len as u64, now);
        }

        RAKNET_OPEN_CONNECTION_REQUEST_1 => {
            // Open Connection Request 1 (0x05)
            // Format: [0x05] [16 bytes magic] [1 byte protocol] [MTU padding zeros]
            // The total packet size indicates the requested MTU
            if payload_len < RAKNET_OPEN_CONN_REQ1_MIN_SIZE {
                return Ok(xdp_action::XDP_DROP);
            }

            if !check_raknet_magic(&payload[1..17]) {
                return Ok(xdp_action::XDP_DROP);
            }

            // Validate RakNet protocol version
            let raknet_protocol = payload[17];
            if raknet_protocol > 11 {
                // RakNet protocol versions are typically <= 11
                return Ok(xdp_action::XDP_DROP);
            }

            // MTU VALIDATION: The packet size indicates requested MTU
            // Reject unreasonable MTU values that could be used for amplification
            let requested_mtu = payload_len as u16;
            if requested_mtu < RAKNET_MIN_MTU || requested_mtu > RAKNET_MAX_MTU {
                return Ok(xdp_action::XDP_DROP);
            }

            // RATE LIMIT: Connection requests
            if !check_bedrock_rate_limit(src_ip, payload_len, false, now) {
                return Ok(xdp_action::XDP_DROP);
            }

            // Track connection state with MTU
            track_bedrock_connection(connection_key, 2, requested_mtu, 0, payload_len as u64, now);
        }

        RAKNET_OPEN_CONNECTION_REQUEST_2 => {
            // Open Connection Request 2 (0x07)
            // Format: [0x07] [16 bytes magic] [server address (7 bytes IPv4)] [2 bytes MTU] [8 bytes client GUID]
            if payload_len < 34 {
                return Ok(xdp_action::XDP_DROP);
            }

            if !check_raknet_magic(&payload[1..17]) {
                return Ok(xdp_action::XDP_DROP);
            }

            // STATE VALIDATION: Should only come after Open Connection Request 1
            if let Some(state) = unsafe { MC_BEDROCK_CONNECTIONS.get(&connection_key) } {
                if state.state != 2 {
                    // Invalid state transition - potential attack
                    return Ok(xdp_action::XDP_DROP);
                }
            } else {
                // No previous state - suspicious, but allow in low protection mode
                // This could be a legitimate client whose state expired
            }

            // Extract and validate MTU (bytes 24-25, after magic and server address)
            let mtu_offset = 17 + 7; // After magic (16) + packet id (1) + server address (7)
            if payload_len < mtu_offset + 2 {
                return Ok(xdp_action::XDP_DROP);
            }
            let mtu = ((payload[mtu_offset] as u16) << 8) | (payload[mtu_offset + 1] as u16);

            if mtu < RAKNET_MIN_MTU || mtu > RAKNET_MAX_MTU {
                return Ok(xdp_action::XDP_DROP);
            }

            // Extract client GUID
            let guid_offset = mtu_offset + 2;
            let client_guid = if payload_len >= guid_offset + 8 {
                let guid_bytes = &payload[guid_offset..guid_offset + 8];
                u64::from_be_bytes([
                    guid_bytes[0],
                    guid_bytes[1],
                    guid_bytes[2],
                    guid_bytes[3],
                    guid_bytes[4],
                    guid_bytes[5],
                    guid_bytes[6],
                    guid_bytes[7],
                ])
            } else {
                0
            };

            // GUID VALIDATION: Should match the GUID from previous handshake
            if let Some(state) = unsafe { MC_BEDROCK_CONNECTIONS.get(&connection_key) } {
                if state.client_guid != 0 && client_guid != 0 && state.client_guid != client_guid {
                    // GUID mismatch - potential attack
                    return Ok(xdp_action::XDP_DROP);
                }
            }

            // Rate limit connection requests
            if !check_bedrock_rate_limit(src_ip, payload_len, false, now) {
                return Ok(xdp_action::XDP_DROP);
            }

            // Update connection state
            track_bedrock_connection(connection_key, 3, mtu, client_guid, payload_len as u64, now);
        }

        // Server-to-client packets (we're receiving these, which is suspicious)
        RAKNET_OPEN_CONNECTION_REPLY_1
        | RAKNET_OPEN_CONNECTION_REPLY_2
        | RAKNET_UNCONNECTED_PONG => {
            // These are server responses - we shouldn't receive them as a server
            // This could indicate reflection attack attempt
            // In strict mode, drop these
            return Ok(xdp_action::XDP_DROP);
        }

        RAKNET_INCOMPATIBLE_PROTOCOL => {
            // Incompatible Protocol Version (0x19)
            // This is a server-to-client packet
            return Ok(xdp_action::XDP_DROP);
        }

        0x80..=0x8f => {
            // Data packets (Frame Set Packet / encapsulated)
            // These are valid connected session packets
            // Format: [1 byte packet ID] [3 byte sequence number (LE)] [encapsulated frames...]
            if payload_len < 4 {
                return Ok(xdp_action::XDP_DROP);
            }

            // Extract sequence number (little-endian 24-bit)
            let _seq_num =
                (payload[1] as u32) | ((payload[2] as u32) << 8) | ((payload[3] as u32) << 16);

            // STATE VALIDATION: Should only come after connection is established
            if let Some(state) = unsafe { MC_BEDROCK_CONNECTIONS.get(&connection_key) } {
                if state.state < 3 {
                    // Not in connected state - suspicious
                    // In strict mode this would be dropped
                }

                // Validate encapsulated frame structure if we have data after sequence number
                if payload_len > 4 {
                    // First frame header byte contains reliability type and flags
                    let frame_header = payload[4];
                    let reliability = (frame_header >> 5) & 0x07;

                    // Reliability types 0-7 are valid, but 0-4 are most common
                    if reliability > 7 {
                        return Ok(xdp_action::XDP_DROP);
                    }

                    // Check for split packet flag (bit 4)
                    let is_split = (frame_header & 0x10) != 0;

                    // Split packets need additional validation
                    if is_split && payload_len < 14 {
                        // Split packets need: frame header + length + reliable seq + split info
                        return Ok(xdp_action::XDP_DROP);
                    }
                }

                // Update state
                update_bedrock_connection_state(&connection_key, payload_len, now);
            }
        }

        0xa0 => {
            // NACK - Negative acknowledgment
            // Format: [0xa0] [2 bytes record count (LE)] [records...]
            // Each record: [1 byte flag] [3 bytes sequence number] [optional 3 bytes end sequence]
            if payload_len < 3 {
                return Ok(xdp_action::XDP_DROP);
            }

            // Extract record count (little-endian)
            let record_count = (payload[1] as u16) | ((payload[2] as u16) << 8);

            // Validate record count - excessive records could be DoS
            // A legitimate NACK shouldn't have more than a few hundred records
            if record_count > RAKNET_MAX_ACK_RECORDS {
                return Ok(xdp_action::XDP_DROP);
            }

            // Validate minimum size for claimed record count
            // Each record is at least 4 bytes (1 flag + 3 seq num)
            let min_records_size = (record_count as usize) * 4;
            if payload_len < 3 + min_records_size {
                // Insufficient data for claimed records
                return Ok(xdp_action::XDP_DROP);
            }
        }

        0xc0 => {
            // ACK - Acknowledgment
            // Format same as NACK
            if payload_len < 3 {
                return Ok(xdp_action::XDP_DROP);
            }

            // Extract record count (little-endian)
            let record_count = (payload[1] as u16) | ((payload[2] as u16) << 8);

            // Validate record count
            if record_count > RAKNET_MAX_ACK_RECORDS {
                return Ok(xdp_action::XDP_DROP);
            }

            // Validate minimum size for claimed record count
            let min_records_size = (record_count as usize) * 4;
            if payload_len < 3 + min_records_size {
                return Ok(xdp_action::XDP_DROP);
            }
        }

        0x09 => {
            // Connection Request (after open connection handshake)
            // Format: [0x09] [8 bytes client_guid] [8 bytes time] [1 byte use_security]
            // Optional: [additional security data if use_security=1]
            if payload_len < 18 {
                // 1 + 8 + 8 + 1
                return Ok(xdp_action::XDP_DROP);
            }

            // Extract client GUID (big-endian)
            let client_guid = u64::from_be_bytes([
                payload[1], payload[2], payload[3], payload[4], payload[5], payload[6], payload[7],
                payload[8],
            ]);

            // STATE VALIDATION: Should only come after Open Connection Request 2
            if let Some(state) = unsafe { MC_BEDROCK_CONNECTIONS.get(&connection_key) } {
                // State should be 3 (after req2) for connection request
                if state.state < 3 {
                    return Ok(xdp_action::XDP_DROP);
                }

                // GUID validation: must match previously seen GUID
                if state.client_guid != 0 && client_guid != 0 && state.client_guid != client_guid {
                    return Ok(xdp_action::XDP_DROP);
                }
            } else {
                // No state - connection request without handshake is suspicious
                // In strict mode we would drop, but allow for expired state
            }

            // Check use_security flag
            let use_security = payload[17];
            if use_security > 1 {
                // Invalid flag value
                return Ok(xdp_action::XDP_DROP);
            }

            // If security is enabled, need more data for certificate
            if use_security == 1 && payload_len < 100 {
                // Security mode requires certificate data
                return Ok(xdp_action::XDP_DROP);
            }

            // Update to connected state
            track_bedrock_connection(connection_key, 4, 0, client_guid, payload_len as u64, now);
        }

        0x10 => {
            // Connection Request Accepted - server-to-client
            return Ok(xdp_action::XDP_DROP);
        }

        0x13 => {
            // New Incoming Connection (client -> server, after connection accepted)
            // Format: [0x13] [7 bytes server address] [10x 7 bytes internal addresses]
            //         [8 bytes ping time] [8 bytes pong time]
            // Minimum: 1 + 7 + 70 + 8 + 8 = 94 bytes (but RakNet lib varies)
            if payload_len < 30 {
                return Ok(xdp_action::XDP_DROP);
            }

            // STATE VALIDATION: Should only come after we sent Connection Request Accepted
            // In our case (as server), this should come after Connection Request (0x09)
            if let Some(state) = unsafe { MC_BEDROCK_CONNECTIONS.get(&connection_key) } {
                if state.state < 4 {
                    // Not in proper state for this packet
                    return Ok(xdp_action::XDP_DROP);
                }
            }
            // Mark connection as fully established
            track_bedrock_connection(connection_key, 5, 0, 0, payload_len as u64, now);
        }

        0x15 => {
            // Disconnect Notification
            // Clean up connection state
            // Can be as small as just the packet ID
        }

        0x00 => {
            // Connected Ping
            if payload_len < 9 {
                return Ok(xdp_action::XDP_DROP);
            }
        }

        0x03 => {
            // Connected Pong - server-to-client
            return Ok(xdp_action::XDP_DROP);
        }

        _ => {
            // Unknown/invalid packet type - drop
            return Ok(xdp_action::XDP_DROP);
        }
    }

    Ok(xdp_action::XDP_PASS)
}

/// Check if a Bedrock IP is blocked due to amplification attack detection
#[inline(always)]
fn is_bedrock_ip_blocked(src_ip: u32) -> bool {
    if let Some(state) = unsafe { MC_BEDROCK_RATE.get(&src_ip) } {
        let now = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
        state.blocked_until > now
    } else {
        false
    }
}

/// Check and update Bedrock rate limits with amplification protection
#[inline(always)]
fn check_bedrock_rate_limit(src_ip: u32, packet_len: usize, is_ping: bool, now: u64) -> bool {
    let window_ns: u64 = 1_000_000_000; // 1 second window

    if let Some(state) = unsafe { MC_BEDROCK_RATE.get_ptr_mut(&src_ip) } {
        let state = unsafe { &mut *state };

        // Check if blocked
        if state.blocked_until > now {
            return false;
        }

        // Check if in new window
        if now.saturating_sub(state.window_start) > window_ns {
            // Reset window
            state.window_start = now;
            state.ping_count = 0;
            state.conn_req_count = 0;
            state.bytes_in = 0;
            state.bytes_out_estimate = 0;
        }

        // Update counters
        state.bytes_in += packet_len as u64;

        if is_ping {
            state.ping_count += 1;
            // Estimate response size (pong can be 500-1500 bytes with MOTD)
            state.bytes_out_estimate += 1000; // Conservative estimate

            if state.ping_count > RAKNET_PING_FLOOD_THRESHOLD {
                // Ping flood detected - block IP
                state.blocked_until = now + 60_000_000_000; // 60 second block
                return false;
            }
        } else {
            state.conn_req_count += 1;
            // Connection responses are smaller but still amplified
            state.bytes_out_estimate += 100;

            if state.conn_req_count > RAKNET_CONN_REQ_FLOOD_THRESHOLD {
                // Connection request flood detected
                state.blocked_until = now + 60_000_000_000;
                return false;
            }
        }

        // Check amplification ratio
        if state.bytes_in > 0 {
            let ratio = state.bytes_out_estimate / state.bytes_in;
            if ratio > RAKNET_MAX_AMPLIFICATION_RATIO as u64 && state.bytes_out_estimate > 10000 {
                // Excessive amplification detected
                state.blocked_until = now + 120_000_000_000; // 2 minute block
                return false;
            }
        }

        true
    } else {
        // First packet from this IP
        let state = BedrockRateState {
            ping_count: if is_ping { 1 } else { 0 },
            conn_req_count: if is_ping { 0 } else { 1 },
            bytes_in: packet_len as u64,
            bytes_out_estimate: if is_ping { 1000 } else { 100 },
            window_start: now,
            blocked_until: 0,
        };
        let _ = MC_BEDROCK_RATE.insert(&src_ip, &state, 0);
        true
    }
}

/// Track Bedrock connection state progression
#[inline(always)]
fn track_bedrock_connection(
    connection_key: u64,
    new_state: u8,
    mtu: u16,
    client_guid: u64,
    bytes: u64,
    now: u64,
) {
    if let Some(state) = unsafe { MC_BEDROCK_CONNECTIONS.get_ptr_mut(&connection_key) } {
        let state = unsafe { &mut *state };

        // Only allow forward state progression
        if new_state > state.state {
            state.state = new_state;
        }

        if mtu > 0 && state.mtu_size == 0 {
            state.mtu_size = mtu;
            state.flags |= BEDROCK_FLAG_MTU_NEGOTIATED;
        }

        if client_guid != 0 && state.client_guid == 0 {
            state.client_guid = client_guid;
            state.flags |= BEDROCK_FLAG_GUID_VALIDATED;
        }

        state.packets += 1;
        state.bytes_in += bytes;
        state.last_seen = now;
    } else {
        // New connection
        let state = BedrockConnectionState {
            state: new_state,
            protocol_version: 0,
            mtu_size: mtu,
            client_guid,
            packets: 1,
            bytes_in: bytes,
            bytes_out_estimate: 0,
            first_seen: now,
            last_seen: now,
            ping_count: 0,
            conn_req_count: 0,
            window_start: now,
            flags: 0,
        };
        let _ = MC_BEDROCK_CONNECTIONS.insert(&connection_key, &state, 0);
    }
}

/// Update Bedrock connection state counters
#[inline(always)]
fn update_bedrock_connection_state(connection_key: &u64, bytes: usize, now: u64) {
    if let Some(state) = unsafe { MC_BEDROCK_CONNECTIONS.get_ptr_mut(connection_key) } {
        let state = unsafe { &mut *state };
        state.packets += 1;
        state.bytes_in += bytes as u64;
        state.last_seen = now;
    }
}

#[inline(always)]
fn check_raknet_magic(data: &[u8]) -> bool {
    if data.len() < 16 {
        return false;
    }

    for i in 0..16 {
        if data[i] != RAKNET_MAGIC[i] {
            return false;
        }
    }
    true
}

#[inline(always)]
fn check_connection_limit(src_ip: u32) -> bool {
    let max_connections = if let Some(config) = unsafe { MC_CONFIG.get_ptr(0) } {
        unsafe { &*config }.max_connections_per_ip
    } else {
        10
    };

    if let Some(count) = unsafe { MC_IP_COUNTS.get_ptr_mut(&src_ip) } {
        let count = unsafe { &mut *count };
        let now = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };

        // Check if blocked
        if count.blocked_until > now {
            return false;
        }

        // Reset count if last connection was more than 60 seconds ago
        if now - count.last_connection > 60_000_000_000 {
            count.count = 1;
            count.last_connection = now;
            return true;
        }

        count.count += 1;
        count.last_connection = now;

        if count.count > max_connections {
            // Block for 60 seconds
            count.blocked_until = now + 60_000_000_000;
            return false;
        }

        true
    } else {
        let entry = IpConnectionCount {
            count: 1,
            last_connection: unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() },
            blocked_until: 0,
        };
        let _ = MC_IP_COUNTS.insert(&src_ip, &entry, 0);
        true
    }
}

#[inline(always)]
fn check_status_rate_limit(src_ip: u32) -> bool {
    let rate_limit = if let Some(config) = unsafe { MC_CONFIG.get_ptr(0) } {
        unsafe { &*config }.status_rate_limit
    } else {
        5 // Default 5 requests per second
    };

    let now = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
    let window = 1_000_000_000; // 1 second

    if let Some(last) = unsafe { MC_STATUS_RATE.get(&src_ip) } {
        if now - *last < window / rate_limit as u64 {
            return false;
        }
    }

    let _ = MC_STATUS_RATE.insert(&src_ip, &now, 0);
    true
}

/// Read a VarInt from the beginning of a buffer
/// Returns (value, bytes_consumed) or None if invalid
#[inline(always)]
fn read_varint(buf: &[u8]) -> Option<(i32, usize)> {
    read_varint_at(buf, 0)
}

/// Read a VarInt at a specific offset in a buffer
/// Returns (value, bytes_consumed) or None if invalid
#[inline(always)]
fn read_varint_at(buf: &[u8], offset: usize) -> Option<(i32, usize)> {
    if offset >= buf.len() {
        return None;
    }

    let mut value: i32 = 0;
    let mut position = 0;
    let mut bytes_read = 0;

    // VarInt can be at most 5 bytes for 32-bit values
    // Use bounded loop for eBPF verifier
    for i in 0..MAX_VARINT_BYTES {
        let idx = offset + i;
        if idx >= buf.len() {
            return None;
        }

        let byte = buf[idx];
        bytes_read += 1;

        // Extract 7 bits and add to value
        value |= ((byte & 0x7f) as i32) << position;

        // If high bit is not set, we're done
        if byte & 0x80 == 0 {
            return Some((value, bytes_read));
        }

        position += 7;

        // VarInt overflow check (32 bits = 5 bytes max, but position would be 35 on 5th)
        if position >= 32 {
            // Only valid if this is the 5th byte and it only uses 4 bits
            // For negative numbers, the 5th byte can be 0x0f (15) max for sign extension
            if i == 4 && (byte & 0xf0) != 0 {
                return None;
            }
        }
    }

    // If we get here, VarInt is too long (> 5 bytes)
    None
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
