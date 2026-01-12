//! XDP Minecraft Protocol Filter
//!
//! Specialized XDP program for filtering Minecraft Java and Bedrock traffic.

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{HashMap, LruHashMap, PerCpuArray},
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
    pub state: u8,           // 0=none, 1=handshake, 2=status, 3=login, 4=play
    pub protocol_version: u32,
    pub packets: u64,
    pub bytes: u64,
    pub last_seen: u64,
    pub flags: u32,
}

/// RakNet magic bytes for Bedrock
const RAKNET_MAGIC: [u8; 16] = [
    0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe,
    0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78,
];

/// Minecraft configuration
#[repr(C)]
pub struct McConfig {
    pub enabled: u32,
    pub java_port: u16,
    pub bedrock_port: u16,
    pub validate_handshake: u32,
    pub max_connections_per_ip: u32,
    pub status_rate_limit: u32,
    pub min_protocol_version: u32,
    pub max_protocol_version: u32,
}

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

/// Minecraft Bedrock connections
#[map]
static MC_BEDROCK_CONNECTIONS: LruHashMap<u64, McConnectionState> =
    LruHashMap::with_max_entries(500_000, 0);

/// Per-IP connection counts
#[map]
static MC_IP_COUNTS: LruHashMap<u32, IpConnectionCount> =
    LruHashMap::with_max_entries(1_000_000, 0);

/// Status request rate limiting
#[map]
static MC_STATUS_RATE: LruHashMap<u32, u64> =
    LruHashMap::with_max_entries(100_000, 0);

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
    ctx: &XdpContext,
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
    let java_port = if let Some(config) = unsafe { MC_CONFIG.get_ptr(0) } {
        let config = unsafe { &*config };
        if config.enabled == 0 {
            return Ok(xdp_action::XDP_PASS);
        }
        config.java_port
    } else {
        MC_JAVA_PORT
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

    // Try to validate Minecraft packet
    let connection_key = ((src_ip as u64) << 16) | (src_port as u64);

    // Parse VarInt length prefix
    let payload = unsafe { core::slice::from_raw_parts(payload_start as *const u8, payload_len) };

    if let Some((packet_len, len_bytes)) = read_varint(payload) {
        if packet_len < 0 || packet_len > 32767 {
            // Invalid packet length
            return Ok(xdp_action::XDP_DROP);
        }

        // Check packet ID
        if len_bytes < payload_len {
            let packet_id = payload[len_bytes];

            // Validate based on connection state
            if let Some(state) = unsafe { MC_JAVA_CONNECTIONS.get(&connection_key) } {
                match state.state {
                    0 => {
                        // Expecting handshake (packet ID 0x00)
                        if packet_id != 0x00 {
                            return Ok(xdp_action::XDP_DROP);
                        }
                    }
                    1 => {
                        // Status state - only status request (0x00) and ping (0x01)
                        if packet_id > 0x01 {
                            return Ok(xdp_action::XDP_DROP);
                        }
                        // Rate limit status requests
                        if packet_id == 0x00 && !check_status_rate_limit(src_ip) {
                            return Ok(xdp_action::XDP_DROP);
                        }
                    }
                    2 => {
                        // Login state
                        if packet_id > 0x04 {
                            return Ok(xdp_action::XDP_DROP);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn process_minecraft_bedrock(
    ctx: &XdpContext,
    data: usize,
    data_end: usize,
    src_ip: u32,
) -> Result<u32, ()> {
    if data + mem::size_of::<UdpHdr>() > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let udp = unsafe { &*(data as *const UdpHdr) };
    let dst_port = u16::from_be(udp.dest);

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

    let payload = unsafe { core::slice::from_raw_parts(payload_start as *const u8, payload_len) };
    let packet_id = payload[0];

    // Validate RakNet packets
    match packet_id {
        0x01 | 0x02 => {
            // Unconnected Ping/Pong - check for RakNet magic
            if payload_len >= 33 {
                if !check_raknet_magic(&payload[17..33]) {
                    return Ok(xdp_action::XDP_DROP);
                }
            } else {
                return Ok(xdp_action::XDP_DROP);
            }

            // Rate limit MOTD requests
            if packet_id == 0x01 && !check_status_rate_limit(src_ip) {
                return Ok(xdp_action::XDP_DROP);
            }
        }
        0x05 | 0x06 | 0x07 | 0x08 => {
            // Connection packets - magic at offset 1
            if payload_len >= 17 {
                if !check_raknet_magic(&payload[1..17]) {
                    return Ok(xdp_action::XDP_DROP);
                }
            } else {
                return Ok(xdp_action::XDP_DROP);
            }
        }
        0x1c => {
            // Unconnected Pong
            if payload_len >= 35 {
                if !check_raknet_magic(&payload[17..33]) {
                    return Ok(xdp_action::XDP_DROP);
                }
            }
        }
        0x80..=0x8f => {
            // Data packets (encapsulated) - allow if valid header
        }
        0xa0 | 0xc0 => {
            // NACK / ACK - allow
        }
        _ => {
            // Unknown packet type
            return Ok(xdp_action::XDP_DROP);
        }
    }

    Ok(xdp_action::XDP_PASS)
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

#[inline(always)]
fn read_varint(buf: &[u8]) -> Option<(i32, usize)> {
    let mut value: i32 = 0;
    let mut position = 0;

    for (i, &byte) in buf.iter().enumerate() {
        value |= ((byte & 0x7f) as i32) << position;

        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }

        position += 7;
        if position >= 32 {
            return None;
        }

        if i >= 4 {
            return None;
        }
    }

    None
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
