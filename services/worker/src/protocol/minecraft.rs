//! Minecraft protocol analysis and filtering

use super::{AnalyzerStats, L7Protocol, PacketMeta, ProtocolAnalyzer, Verdict};
use parking_lot::RwLock;
use pistonprotection_common::error::Result;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{debug, warn};

/// Minecraft Java Edition packet types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MinecraftJavaPacket {
    /// Handshake packet (0x00)
    Handshake,
    /// Status request (0x00 in status state)
    StatusRequest,
    /// Ping (0x01 in status state)
    StatusPing,
    /// Login start (0x00 in login state)
    LoginStart,
    /// Unknown packet
    Unknown(u8),
}

/// Minecraft Bedrock Edition packet types (RakNet)
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MinecraftBedrockPacket {
    /// Unconnected Ping (0x01)
    UnconnectedPing,
    /// Unconnected Pong (0x1c)
    UnconnectedPong,
    /// Open Connection Request 1 (0x05)
    OpenConnectionRequest1,
    /// Open Connection Reply 1 (0x06)
    OpenConnectionReply1,
    /// Open Connection Request 2 (0x07)
    OpenConnectionRequest2,
    /// Open Connection Reply 2 (0x08)
    OpenConnectionReply2,
    /// Unknown packet
    Unknown(u8),
}

/// RakNet magic bytes
pub const RAKNET_MAGIC: [u8; 16] = [
    0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe, 0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78,
];

/// Check if payload is Minecraft Java protocol
pub fn is_minecraft_java(payload: &[u8]) -> bool {
    if payload.is_empty() {
        return false;
    }

    // Minecraft Java packets start with a VarInt length
    // Try to parse it and validate
    if let Some((len, bytes_read)) = read_varint(payload) {
        // Reasonable packet length (not too big, not negative)
        if len > 0 && len < 32767 && bytes_read + len as usize <= payload.len() {
            // Check if next byte could be a valid packet ID
            if bytes_read < payload.len() {
                let packet_id = payload[bytes_read];
                // Common handshake/status packet IDs are 0x00, 0x01
                return packet_id <= 0x10;
            }
        }
    }

    false
}

/// Check if payload is Minecraft Bedrock (RakNet) protocol
pub fn is_minecraft_bedrock(payload: &[u8]) -> bool {
    if payload.len() < 17 {
        return false;
    }

    // Check for RakNet magic in common packet types
    let packet_id = payload[0];

    match packet_id {
        0x01 | 0x02 => {
            // Unconnected Ping/Pong - magic at offset 17
            if payload.len() >= 33 {
                return &payload[17..33] == &RAKNET_MAGIC;
            }
        }
        0x05 | 0x06 | 0x07 | 0x08 => {
            // Connection packets - magic at offset 1
            if payload.len() >= 17 {
                return &payload[1..17] == &RAKNET_MAGIC;
            }
        }
        0x1c => {
            // Unconnected Pong - magic after timestamp and server GUID
            if payload.len() >= 35 {
                return &payload[17..33] == &RAKNET_MAGIC;
            }
        }
        _ => {}
    }

    false
}

/// Read a VarInt from the buffer
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
    }

    None
}

/// Minecraft Java protocol analyzer
pub struct MinecraftJavaAnalyzer {
    stats: RwLock<AnalyzerStats>,
    /// Maximum connections per IP
    max_connections_per_ip: u32,
    /// Rate limit status pings per second
    status_rate_limit: u32,
    /// Validate handshake packets
    validate_handshake: bool,
}

impl MinecraftJavaAnalyzer {
    pub fn new() -> Self {
        Self {
            stats: RwLock::new(AnalyzerStats::default()),
            max_connections_per_ip: 10,
            status_rate_limit: 5,
            validate_handshake: true,
        }
    }

    /// Parse a Minecraft Java handshake packet
    fn parse_handshake(&self, payload: &[u8]) -> Option<MinecraftJavaHandshake> {
        // Skip packet length
        let (_, len_size) = read_varint(payload)?;
        let rest = &payload[len_size..];

        // Packet ID should be 0x00
        if rest.is_empty() || rest[0] != 0x00 {
            return None;
        }

        let rest = &rest[1..];

        // Protocol version
        let (protocol_version, pv_size) = read_varint(rest)?;
        let rest = &rest[pv_size..];

        // Server address (string with length prefix)
        let (addr_len, al_size) = read_varint(rest)?;
        if addr_len < 0 || addr_len > 255 {
            return None;
        }
        let addr_len = addr_len as usize;
        let rest = &rest[al_size..];

        if rest.len() < addr_len + 3 {
            return None;
        }

        let server_address = std::str::from_utf8(&rest[..addr_len]).ok()?.to_string();
        let rest = &rest[addr_len..];

        // Server port (unsigned short, big endian)
        let server_port = u16::from_be_bytes([rest[0], rest[1]]);
        let rest = &rest[2..];

        // Next state (VarInt: 1 = status, 2 = login)
        let (next_state, _) = read_varint(rest)?;

        Some(MinecraftJavaHandshake {
            protocol_version: protocol_version as u32,
            server_address,
            server_port,
            next_state: next_state as u8,
        })
    }

    /// Validate a handshake packet
    fn validate_handshake(&self, handshake: &MinecraftJavaHandshake) -> bool {
        // Check protocol version is in valid range
        // Current versions are roughly 760-770+ for 1.19-1.21
        if handshake.protocol_version == 0 {
            return false;
        }

        // Check server address is not too long or contains invalid chars
        if handshake.server_address.len() > 255 {
            return false;
        }

        // Check next state is valid (1 = status, 2 = login)
        if handshake.next_state != 1 && handshake.next_state != 2 {
            return false;
        }

        true
    }
}

/// Parsed Minecraft Java handshake
#[derive(Debug)]
struct MinecraftJavaHandshake {
    protocol_version: u32,
    server_address: String,
    server_port: u16,
    next_state: u8,
}

impl ProtocolAnalyzer for MinecraftJavaAnalyzer {
    fn protocol(&self) -> L7Protocol {
        L7Protocol::MinecraftJava
    }

    fn can_handle(&self, meta: &PacketMeta, payload: &[u8]) -> bool {
        meta.dst_port == 25565 || is_minecraft_java(payload)
    }

    fn analyze(&self, meta: &PacketMeta, payload: &[u8]) -> Result<Verdict> {
        let mut stats = self.stats.write();
        stats.packets_analyzed += 1;
        stats.bytes_analyzed += payload.len() as u64;

        // Try to parse as handshake
        if self.validate_handshake {
            if let Some(handshake) = self.parse_handshake(payload) {
                if !self.validate_handshake(&handshake) {
                    debug!(
                        src = %meta.src_ip,
                        protocol_version = handshake.protocol_version,
                        "Invalid Minecraft handshake"
                    );
                    stats.packets_dropped += 1;
                    return Ok(Verdict::Drop);
                }
            }
        }

        stats.packets_passed += 1;
        Ok(Verdict::Pass)
    }

    fn stats(&self) -> AnalyzerStats {
        self.stats.read().clone()
    }
}

/// Minecraft Bedrock (RakNet) protocol analyzer
pub struct MinecraftBedrockAnalyzer {
    stats: RwLock<AnalyzerStats>,
    /// Validate RakNet magic
    validate_magic: bool,
    /// Rate limit MOTD requests
    motd_rate_limit: u32,
}

impl MinecraftBedrockAnalyzer {
    pub fn new() -> Self {
        Self {
            stats: RwLock::new(AnalyzerStats::default()),
            validate_magic: true,
            motd_rate_limit: 5,
        }
    }

    /// Parse RakNet packet type
    fn parse_packet_type(&self, payload: &[u8]) -> MinecraftBedrockPacket {
        if payload.is_empty() {
            return MinecraftBedrockPacket::Unknown(0);
        }

        match payload[0] {
            0x01 => MinecraftBedrockPacket::UnconnectedPing,
            0x1c => MinecraftBedrockPacket::UnconnectedPong,
            0x05 => MinecraftBedrockPacket::OpenConnectionRequest1,
            0x06 => MinecraftBedrockPacket::OpenConnectionReply1,
            0x07 => MinecraftBedrockPacket::OpenConnectionRequest2,
            0x08 => MinecraftBedrockPacket::OpenConnectionReply2,
            other => MinecraftBedrockPacket::Unknown(other),
        }
    }

    /// Validate RakNet magic in packet
    fn validate_magic(&self, payload: &[u8], packet_type: MinecraftBedrockPacket) -> bool {
        let magic_offset = match packet_type {
            MinecraftBedrockPacket::UnconnectedPing | MinecraftBedrockPacket::UnconnectedPong => 17,
            MinecraftBedrockPacket::OpenConnectionRequest1
            | MinecraftBedrockPacket::OpenConnectionReply1
            | MinecraftBedrockPacket::OpenConnectionRequest2
            | MinecraftBedrockPacket::OpenConnectionReply2 => 1,
            MinecraftBedrockPacket::Unknown(_) => return true, // Don't validate unknown packets
        };

        if payload.len() < magic_offset + 16 {
            return false;
        }

        &payload[magic_offset..magic_offset + 16] == &RAKNET_MAGIC
    }
}

impl ProtocolAnalyzer for MinecraftBedrockAnalyzer {
    fn protocol(&self) -> L7Protocol {
        L7Protocol::MinecraftBedrock
    }

    fn can_handle(&self, meta: &PacketMeta, payload: &[u8]) -> bool {
        meta.dst_port == 19132 || is_minecraft_bedrock(payload)
    }

    fn analyze(&self, meta: &PacketMeta, payload: &[u8]) -> Result<Verdict> {
        let mut stats = self.stats.write();
        stats.packets_analyzed += 1;
        stats.bytes_analyzed += payload.len() as u64;

        let packet_type = self.parse_packet_type(payload);

        // Validate magic
        if self.validate_magic {
            if !self.validate_magic(payload, packet_type) {
                debug!(
                    src = %meta.src_ip,
                    packet_type = ?packet_type,
                    "Invalid RakNet magic"
                );
                stats.packets_dropped += 1;
                return Ok(Verdict::Drop);
            }
        }

        stats.packets_passed += 1;
        Ok(Verdict::Pass)
    }

    fn stats(&self) -> AnalyzerStats {
        self.stats.read().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_varint() {
        // Single byte
        assert_eq!(read_varint(&[0x00]), Some((0, 1)));
        assert_eq!(read_varint(&[0x01]), Some((1, 1)));
        assert_eq!(read_varint(&[0x7f]), Some((127, 1)));

        // Two bytes
        assert_eq!(read_varint(&[0x80, 0x01]), Some((128, 2)));
        assert_eq!(read_varint(&[0xff, 0x01]), Some((255, 2)));
    }

    #[test]
    fn test_is_minecraft_bedrock() {
        // Valid unconnected ping with magic
        let mut ping = vec![0x01; 33];
        ping[17..33].copy_from_slice(&RAKNET_MAGIC);
        assert!(is_minecraft_bedrock(&ping));

        // Invalid - no magic
        let invalid = vec![0x01; 33];
        assert!(!is_minecraft_bedrock(&invalid));
    }
}
