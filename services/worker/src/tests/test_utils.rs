//! Test utilities for worker tests

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Test configuration constants
pub mod constants {
    pub const TEST_BACKEND_ID: &str = "test-backend-456";
    pub const TEST_INTERFACE: &str = "lo";
    pub const MINECRAFT_PORT: u16 = 25565;
    pub const MINECRAFT_BEDROCK_PORT: u16 = 19132;
}

/// Create a test IPv4 packet
pub fn create_ipv4_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
    is_tcp: bool,
) -> Vec<u8> {
    let mut packet = Vec::new();

    // IP header (20 bytes, no options)
    let ip_header_len = 20u8;
    let total_len = ip_header_len as u16 + if is_tcp { 20 } else { 8 } + payload.len() as u16;

    // Version (4) + IHL (5)
    packet.push(0x45);
    // DSCP + ECN
    packet.push(0x00);
    // Total length
    packet.extend_from_slice(&total_len.to_be_bytes());
    // Identification
    packet.extend_from_slice(&[0x00, 0x00]);
    // Flags + Fragment offset
    packet.extend_from_slice(&[0x40, 0x00]); // Don't fragment
    // TTL
    packet.push(64);
    // Protocol (6 = TCP, 17 = UDP)
    packet.push(if is_tcp { 6 } else { 17 });
    // Header checksum (placeholder)
    packet.extend_from_slice(&[0x00, 0x00]);
    // Source IP
    packet.extend_from_slice(&src_ip.octets());
    // Destination IP
    packet.extend_from_slice(&dst_ip.octets());

    if is_tcp {
        // TCP header (20 bytes, no options)
        packet.extend_from_slice(&src_port.to_be_bytes());
        packet.extend_from_slice(&dst_port.to_be_bytes());
        // Sequence number
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        // Acknowledgment number
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        // Data offset (5) + Reserved + Flags (SYN)
        packet.push(0x50);
        packet.push(0x02); // SYN flag
        // Window size
        packet.extend_from_slice(&[0xff, 0xff]);
        // Checksum (placeholder)
        packet.extend_from_slice(&[0x00, 0x00]);
        // Urgent pointer
        packet.extend_from_slice(&[0x00, 0x00]);
    } else {
        // UDP header (8 bytes)
        packet.extend_from_slice(&src_port.to_be_bytes());
        packet.extend_from_slice(&dst_port.to_be_bytes());
        // Length
        let udp_len = 8u16 + payload.len() as u16;
        packet.extend_from_slice(&udp_len.to_be_bytes());
        // Checksum (placeholder)
        packet.extend_from_slice(&[0x00, 0x00]);
    }

    // Payload
    packet.extend_from_slice(payload);

    packet
}

/// Create a Minecraft Java handshake packet
pub fn create_minecraft_java_handshake(
    protocol_version: u32,
    server_address: &str,
    server_port: u16,
    next_state: u8,
) -> Vec<u8> {
    let mut packet = Vec::new();

    // Packet ID (0x00 for handshake)
    packet.push(0x00);

    // Protocol version (VarInt)
    write_varint(&mut packet, protocol_version as i32);

    // Server address (string)
    write_varint(&mut packet, server_address.len() as i32);
    packet.extend_from_slice(server_address.as_bytes());

    // Server port (unsigned short, big endian)
    packet.extend_from_slice(&server_port.to_be_bytes());

    // Next state (VarInt: 1 = status, 2 = login)
    write_varint(&mut packet, next_state as i32);

    // Prepend packet length
    let len = packet.len();
    let mut final_packet = Vec::new();
    write_varint(&mut final_packet, len as i32);
    final_packet.extend_from_slice(&packet);

    final_packet
}

/// Create a Minecraft Bedrock (RakNet) unconnected ping
pub fn create_minecraft_bedrock_ping(time: u64, client_guid: u64) -> Vec<u8> {
    let mut packet = Vec::new();

    // Packet ID (0x01 = Unconnected Ping)
    packet.push(0x01);

    // Time since start
    packet.extend_from_slice(&time.to_be_bytes());

    // RakNet magic
    packet.extend_from_slice(&crate::protocol::minecraft::RAKNET_MAGIC);

    // Client GUID
    packet.extend_from_slice(&client_guid.to_be_bytes());

    packet
}

/// Create RakNet open connection request
pub fn create_raknet_open_connection_request() -> Vec<u8> {
    let mut packet = Vec::new();

    // Packet ID (0x05 = Open Connection Request 1)
    packet.push(0x05);

    // RakNet magic
    packet.extend_from_slice(&crate::protocol::minecraft::RAKNET_MAGIC);

    // Protocol version (11 is common)
    packet.push(11);

    // MTU padding (remaining bytes to indicate MTU)
    packet.extend_from_slice(&vec![0x00; 1400]);

    packet
}

/// Write a VarInt to a buffer
fn write_varint(buf: &mut Vec<u8>, mut value: i32) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if value == 0 {
            break;
        }
    }
}

/// Test packet metadata
#[derive(Debug, Clone)]
pub struct TestPacketMeta {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub size: usize,
}

impl Default for TestPacketMeta {
    fn default() -> Self {
        Self {
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            src_port: 12345,
            dst_port: 25565,
            protocol: 6, // TCP
            size: 100,
        }
    }
}

impl TestPacketMeta {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn udp(mut self) -> Self {
        self.protocol = 17;
        self
    }

    pub fn tcp(mut self) -> Self {
        self.protocol = 6;
        self
    }

    pub fn to_port(mut self, port: u16) -> Self {
        self.dst_port = port;
        self
    }

    pub fn from_ip(mut self, ip: IpAddr) -> Self {
        self.src_ip = ip;
        self
    }
}

/// Mock network interface
#[derive(Debug, Clone)]
pub struct MockNetworkInterface {
    pub name: String,
    pub index: u32,
    pub mac: [u8; 6],
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
}

impl Default for MockNetworkInterface {
    fn default() -> Self {
        Self {
            name: "eth0".to_string(),
            index: 2,
            mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            ipv4: Some(Ipv4Addr::new(10, 0, 0, 1)),
            ipv6: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_ipv4_tcp_packet() {
        let packet = create_ipv4_packet(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(10, 0, 0, 1),
            12345,
            80,
            b"hello",
            true,
        );

        // IP header (20) + TCP header (20) + payload (5)
        assert_eq!(packet.len(), 45);
        // Version + IHL
        assert_eq!(packet[0], 0x45);
        // Protocol = TCP
        assert_eq!(packet[9], 6);
    }

    #[test]
    fn test_create_ipv4_udp_packet() {
        let packet = create_ipv4_packet(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(10, 0, 0, 1),
            12345,
            53,
            b"query",
            false,
        );

        // IP header (20) + UDP header (8) + payload (5)
        assert_eq!(packet.len(), 33);
        // Protocol = UDP
        assert_eq!(packet[9], 17);
    }

    #[test]
    fn test_create_minecraft_handshake() {
        let handshake = create_minecraft_java_handshake(
            762, // 1.19.4
            "play.example.com",
            25565,
            2, // Login
        );

        // Should be valid VarInt prefixed packet
        assert!(!handshake.is_empty());
        // First byte should be packet length VarInt
    }

    #[test]
    fn test_create_bedrock_ping() {
        let ping = create_minecraft_bedrock_ping(12345, 0xDEADBEEF);

        assert_eq!(ping[0], 0x01); // Packet ID
        // Should contain RakNet magic
        assert!(ping.len() >= 25);
    }

    #[test]
    fn test_packet_meta_builder() {
        let meta = TestPacketMeta::new().udp().to_port(19132);

        assert_eq!(meta.protocol, 17);
        assert_eq!(meta.dst_port, 19132);
    }
}

// ============================================================================
// Additional test packet creation functions for security testing
// ============================================================================

/// Create a Minecraft Java TRANSFER handshake (next_state = 3)
/// This is for testing 1.20.5+ transfer state support
pub fn create_minecraft_transfer_handshake(
    protocol_version: u32,
    server_address: &str,
    server_port: u16,
) -> Vec<u8> {
    create_minecraft_java_handshake(protocol_version, server_address, server_port, 3)
}

/// Create a malformed handshake with negative packet length (varint attack)
/// This should be detected and dropped by the filter
pub fn create_malformed_negative_length_packet() -> Vec<u8> {
    // VarInt encoding of -1 is 0xFF 0xFF 0xFF 0xFF 0x0F
    // This creates an extremely large "length" that's negative when interpreted
    vec![0xFF, 0xFF, 0xFF, 0xFF, 0x0F, 0x00]
}

/// Create a malformed handshake with extremely long varint
/// (more than 5 bytes, which is invalid for a VarInt)
pub fn create_malformed_overlong_varint() -> Vec<u8> {
    // 6-byte varint (invalid - max is 5 bytes)
    vec![0x80, 0x80, 0x80, 0x80, 0x80, 0x01]
}

/// Create a handshake with negative packet ID (attack vector)
pub fn create_negative_packet_id_handshake() -> Vec<u8> {
    let mut packet = Vec::new();

    // Valid packet length (small)
    packet.push(0x10);

    // Negative packet ID as VarInt (-1 = 0xFF 0xFF 0xFF 0xFF 0x0F)
    packet.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0x0F]);

    // Garbage payload
    packet.extend_from_slice(&[0x00; 10]);

    packet
}

/// Create a handshake with invalid next_state value
pub fn create_invalid_next_state_handshake(
    protocol_version: u32,
    server_address: &str,
    server_port: u16,
    invalid_state: u8,
) -> Vec<u8> {
    create_minecraft_java_handshake(protocol_version, server_address, server_port, invalid_state)
}

/// Create a fragmented Minecraft packet (first fragment)
pub fn create_fragmented_handshake_part1(
    protocol_version: u32,
    server_address: &str,
) -> Vec<u8> {
    let full_handshake = create_minecraft_java_handshake(protocol_version, server_address, 25565, 2);
    // Return first half
    full_handshake[..full_handshake.len() / 2].to_vec()
}

/// Create a fragmented Minecraft packet (second fragment)
pub fn create_fragmented_handshake_part2(
    protocol_version: u32,
    server_address: &str,
) -> Vec<u8> {
    let full_handshake = create_minecraft_java_handshake(protocol_version, server_address, 25565, 2);
    // Return second half
    full_handshake[full_handshake.len() / 2..].to_vec()
}

/// Create a RakNet NAK flood packet (attack vector)
pub fn create_raknet_nak_packet(sequence_numbers: &[u32]) -> Vec<u8> {
    let mut packet = Vec::new();

    // NAK packet ID (0xA0)
    packet.push(0xA0);

    // Record count (little endian 16-bit)
    let count = sequence_numbers.len() as u16;
    packet.extend_from_slice(&count.to_le_bytes());

    // Sequence number ranges (simplified - all single entries)
    for &seq in sequence_numbers {
        // Range flag = 0 (single)
        packet.push(0x00);
        // Sequence number (24-bit little endian)
        packet.push((seq & 0xFF) as u8);
        packet.push(((seq >> 8) & 0xFF) as u8);
        packet.push(((seq >> 16) & 0xFF) as u8);
    }

    packet
}

/// Create a RakNet amplification attack packet
pub fn create_raknet_amplification_packet() -> Vec<u8> {
    let mut packet = Vec::new();

    // Unconnected ping (0x01) - used for amplification
    packet.push(0x01);

    // Time
    packet.extend_from_slice(&0u64.to_be_bytes());

    // RakNet magic
    packet.extend_from_slice(&crate::protocol::minecraft::RAKNET_MAGIC);

    // Client GUID
    packet.extend_from_slice(&0xFFFFFFFFFFFFFFFFu64.to_be_bytes());

    packet
}

/// Create a Minecraft status request packet
pub fn create_minecraft_status_request() -> Vec<u8> {
    let mut packet = Vec::new();

    // Packet length (1)
    packet.push(0x01);
    // Packet ID (0x00 for status request)
    packet.push(0x00);

    packet
}

/// Create a Minecraft ping packet
pub fn create_minecraft_ping(payload: u64) -> Vec<u8> {
    let mut packet = Vec::new();

    // Packet length (9 - 1 byte ID + 8 byte long)
    packet.push(0x09);
    // Packet ID (0x01 for ping)
    packet.push(0x01);
    // Payload (long, big endian)
    packet.extend_from_slice(&payload.to_be_bytes());

    packet
}

/// Create a Minecraft login start packet
pub fn create_minecraft_login_start(username: &str) -> Vec<u8> {
    let mut packet = Vec::new();

    // Packet ID (0x00 for login start)
    packet.push(0x00);

    // Username (string with VarInt length prefix)
    write_varint_pub(&mut packet, username.len() as i32);
    packet.extend_from_slice(username.as_bytes());

    // Prepend packet length
    let len = packet.len();
    let mut final_packet = Vec::new();
    write_varint_pub(&mut final_packet, len as i32);
    final_packet.extend_from_slice(&packet);

    final_packet
}

/// Public VarInt writer for use in test modules
pub fn write_varint_pub(buf: &mut Vec<u8>, mut value: i32) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if value == 0 {
            break;
        }
    }
}
