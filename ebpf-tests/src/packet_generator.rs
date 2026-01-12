//! Packet generation utilities for testing XDP filters
//!
//! Provides builders for creating test packets of various protocols.

use std::net::Ipv4Addr;
// Note: Ipv6Addr will be needed when IPv6 support is added

/// Ethernet header constants
pub const ETH_P_IP: u16 = 0x0800;
pub const ETH_P_IPV6: u16 = 0x86DD;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

/// TCP flags
pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;
pub const TCP_URG: u8 = 0x20;
pub const TCP_ECE: u8 = 0x40;
pub const TCP_CWR: u8 = 0x80;

/// RakNet magic bytes
pub const RAKNET_MAGIC: [u8; 16] = [
    0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe, 0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78,
];

/// RakNet packet IDs
pub const RAKNET_UNCONNECTED_PING: u8 = 0x01;
pub const RAKNET_UNCONNECTED_PING_OPEN: u8 = 0x02;
pub const RAKNET_OPEN_CONNECTION_REQUEST_1: u8 = 0x05;
pub const RAKNET_OPEN_CONNECTION_REQUEST_2: u8 = 0x07;
pub const RAKNET_UNCONNECTED_PONG: u8 = 0x1c;

/// Ethernet frame builder
#[derive(Debug, Clone)]
pub struct EthernetFrame {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ether_type: u16,
    pub payload: Vec<u8>,
}

impl Default for EthernetFrame {
    fn default() -> Self {
        Self {
            dst_mac: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            src_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            ether_type: ETH_P_IP,
            payload: Vec::new(),
        }
    }
}

impl EthernetFrame {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_dst_mac(mut self, mac: [u8; 6]) -> Self {
        self.dst_mac = mac;
        self
    }

    pub fn with_src_mac(mut self, mac: [u8; 6]) -> Self {
        self.src_mac = mac;
        self
    }

    pub fn with_ether_type(mut self, ether_type: u16) -> Self {
        self.ether_type = ether_type;
        self
    }

    pub fn with_payload(mut self, payload: Vec<u8>) -> Self {
        self.payload = payload;
        self
    }

    pub fn build(&self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(14 + self.payload.len());
        packet.extend_from_slice(&self.dst_mac);
        packet.extend_from_slice(&self.src_mac);
        packet.extend_from_slice(&self.ether_type.to_be_bytes());
        packet.extend_from_slice(&self.payload);
        packet
    }
}

/// IPv4 packet builder
#[derive(Debug, Clone)]
pub struct Ipv4Packet {
    pub version: u8,
    pub ihl: u8,
    pub tos: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub options: Vec<u8>,
    pub payload: Vec<u8>,
}

impl Default for Ipv4Packet {
    fn default() -> Self {
        Self {
            version: 4,
            ihl: 5,
            tos: 0,
            total_length: 0,
            identification: 0,
            flags: 0,
            fragment_offset: 0,
            ttl: 64,
            protocol: IPPROTO_TCP,
            checksum: 0,
            src_ip: Ipv4Addr::new(192, 168, 1, 100),
            dst_ip: Ipv4Addr::new(192, 168, 1, 1),
            options: Vec::new(),
            payload: Vec::new(),
        }
    }
}

impl Ipv4Packet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_src_ip(mut self, ip: Ipv4Addr) -> Self {
        self.src_ip = ip;
        self
    }

    pub fn with_dst_ip(mut self, ip: Ipv4Addr) -> Self {
        self.dst_ip = ip;
        self
    }

    pub fn with_protocol(mut self, protocol: u8) -> Self {
        self.protocol = protocol;
        self
    }

    pub fn with_ttl(mut self, ttl: u8) -> Self {
        self.ttl = ttl;
        self
    }

    pub fn with_fragment(mut self, flags: u8, offset: u16) -> Self {
        self.flags = flags;
        self.fragment_offset = offset;
        self
    }

    pub fn with_payload(mut self, payload: Vec<u8>) -> Self {
        self.payload = payload;
        self
    }

    pub fn build(&self) -> Vec<u8> {
        let ihl = 5 + (self.options.len() / 4) as u8;
        let header_len = (ihl as usize) * 4;
        let total_len = header_len + self.payload.len();

        let mut packet = Vec::with_capacity(total_len);

        // Version + IHL
        packet.push((self.version << 4) | ihl);
        // TOS
        packet.push(self.tos);
        // Total length
        packet.extend_from_slice(&(total_len as u16).to_be_bytes());
        // Identification
        packet.extend_from_slice(&self.identification.to_be_bytes());
        // Flags + Fragment offset
        let frag_field = ((self.flags as u16) << 13) | (self.fragment_offset & 0x1fff);
        packet.extend_from_slice(&frag_field.to_be_bytes());
        // TTL
        packet.push(self.ttl);
        // Protocol
        packet.push(self.protocol);
        // Checksum (will compute later)
        packet.extend_from_slice(&[0, 0]);
        // Source IP
        packet.extend_from_slice(&self.src_ip.octets());
        // Destination IP
        packet.extend_from_slice(&self.dst_ip.octets());
        // Options
        packet.extend_from_slice(&self.options);
        // Pad options to 32-bit boundary
        while packet.len() < header_len {
            packet.push(0);
        }

        // Compute checksum
        let checksum = compute_ip_checksum(&packet[..header_len]);
        packet[10] = (checksum >> 8) as u8;
        packet[11] = (checksum & 0xff) as u8;

        // Payload
        packet.extend_from_slice(&self.payload);

        packet
    }
}

/// TCP segment builder
#[derive(Debug, Clone)]
pub struct TcpSegment {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub data_offset: u8,
    pub flags: u8,
    pub window: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
    pub options: Vec<u8>,
    pub payload: Vec<u8>,
}

impl Default for TcpSegment {
    fn default() -> Self {
        Self {
            src_port: 12345,
            dst_port: 80,
            seq_num: 1000,
            ack_num: 0,
            data_offset: 5,
            flags: 0,
            window: 65535,
            checksum: 0,
            urgent_ptr: 0,
            options: Vec::new(),
            payload: Vec::new(),
        }
    }
}

impl TcpSegment {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_src_port(mut self, port: u16) -> Self {
        self.src_port = port;
        self
    }

    pub fn with_dst_port(mut self, port: u16) -> Self {
        self.dst_port = port;
        self
    }

    pub fn with_seq(mut self, seq: u32) -> Self {
        self.seq_num = seq;
        self
    }

    pub fn with_ack(mut self, ack: u32) -> Self {
        self.ack_num = ack;
        self
    }

    pub fn with_flags(mut self, flags: u8) -> Self {
        self.flags = flags;
        self
    }

    pub fn with_window(mut self, window: u16) -> Self {
        self.window = window;
        self
    }

    pub fn syn(mut self) -> Self {
        self.flags = TCP_SYN;
        self
    }

    pub fn syn_ack(mut self) -> Self {
        self.flags = TCP_SYN | TCP_ACK;
        self
    }

    pub fn ack(mut self) -> Self {
        self.flags = TCP_ACK;
        self
    }

    pub fn fin_ack(mut self) -> Self {
        self.flags = TCP_FIN | TCP_ACK;
        self
    }

    pub fn rst(mut self) -> Self {
        self.flags = TCP_RST;
        self
    }

    pub fn with_payload(mut self, payload: Vec<u8>) -> Self {
        self.payload = payload;
        self
    }

    pub fn with_options(mut self, options: Vec<u8>) -> Self {
        self.options = options;
        self
    }

    pub fn build(&self) -> Vec<u8> {
        let data_offset = 5 + (self.options.len() / 4) as u8;
        let header_len = (data_offset as usize) * 4;

        let mut segment = Vec::with_capacity(header_len + self.payload.len());

        // Source port
        segment.extend_from_slice(&self.src_port.to_be_bytes());
        // Destination port
        segment.extend_from_slice(&self.dst_port.to_be_bytes());
        // Sequence number
        segment.extend_from_slice(&self.seq_num.to_be_bytes());
        // Acknowledgment number
        segment.extend_from_slice(&self.ack_num.to_be_bytes());
        // Data offset + reserved + flags
        let doff_flags = ((data_offset as u16) << 12) | (self.flags as u16);
        segment.extend_from_slice(&doff_flags.to_be_bytes());
        // Window
        segment.extend_from_slice(&self.window.to_be_bytes());
        // Checksum (placeholder)
        segment.extend_from_slice(&[0, 0]);
        // Urgent pointer
        segment.extend_from_slice(&self.urgent_ptr.to_be_bytes());
        // Options
        segment.extend_from_slice(&self.options);
        // Pad to 32-bit boundary
        while segment.len() < header_len {
            segment.push(0);
        }
        // Payload
        segment.extend_from_slice(&self.payload);

        segment
    }
}

/// UDP datagram builder
#[derive(Debug, Clone)]
pub struct UdpDatagram {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
    pub payload: Vec<u8>,
}

impl Default for UdpDatagram {
    fn default() -> Self {
        Self {
            src_port: 12345,
            dst_port: 19132, // Minecraft Bedrock default
            length: 8,
            checksum: 0,
            payload: Vec::new(),
        }
    }
}

impl UdpDatagram {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_src_port(mut self, port: u16) -> Self {
        self.src_port = port;
        self
    }

    pub fn with_dst_port(mut self, port: u16) -> Self {
        self.dst_port = port;
        self
    }

    pub fn with_payload(mut self, payload: Vec<u8>) -> Self {
        self.length = 8 + payload.len() as u16;
        self.payload = payload;
        self
    }

    pub fn build(&self) -> Vec<u8> {
        let mut datagram = Vec::with_capacity(8 + self.payload.len());

        // Source port
        datagram.extend_from_slice(&self.src_port.to_be_bytes());
        // Destination port
        datagram.extend_from_slice(&self.dst_port.to_be_bytes());
        // Length
        let len = 8 + self.payload.len() as u16;
        datagram.extend_from_slice(&len.to_be_bytes());
        // Checksum
        datagram.extend_from_slice(&[0, 0]);
        // Payload
        datagram.extend_from_slice(&self.payload);

        datagram
    }
}

/// Minecraft VarInt encoding
pub fn encode_varint(value: i32) -> Vec<u8> {
    let mut result = Vec::new();
    let mut val = value as u32;

    loop {
        let mut byte = (val & 0x7f) as u8;
        val >>= 7;
        if val != 0 {
            byte |= 0x80;
        }
        result.push(byte);
        if val == 0 {
            break;
        }
    }

    result
}

/// Minecraft VarInt decoding
pub fn decode_varint(data: &[u8]) -> Option<(i32, usize)> {
    let mut value: i32 = 0;
    let mut position = 0;
    let mut bytes_read = 0;

    for &byte in data.iter().take(5) {
        bytes_read += 1;
        value |= ((byte & 0x7f) as i32) << position;

        if byte & 0x80 == 0 {
            return Some((value, bytes_read));
        }

        position += 7;
        if position >= 32 {
            return None;
        }
    }

    None
}

/// Minecraft Java handshake packet builder
#[derive(Debug, Clone)]
pub struct MinecraftHandshake {
    pub protocol_version: i32,
    pub server_address: String,
    pub server_port: u16,
    pub next_state: i32, // 1 = status, 2 = login
}

impl Default for MinecraftHandshake {
    fn default() -> Self {
        Self {
            protocol_version: 765, // 1.20.4
            server_address: "localhost".to_string(),
            server_port: 25565,
            next_state: 2, // Login
        }
    }
}

impl MinecraftHandshake {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_protocol(mut self, version: i32) -> Self {
        self.protocol_version = version;
        self
    }

    pub fn with_address(mut self, addr: &str) -> Self {
        self.server_address = addr.to_string();
        self
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.server_port = port;
        self
    }

    pub fn with_next_state(mut self, state: i32) -> Self {
        self.next_state = state;
        self
    }

    pub fn status(mut self) -> Self {
        self.next_state = 1;
        self
    }

    pub fn login(mut self) -> Self {
        self.next_state = 2;
        self
    }

    pub fn build(&self) -> Vec<u8> {
        let mut packet_data = Vec::new();

        // Packet ID (0x00 for handshake)
        packet_data.extend(encode_varint(0x00));
        // Protocol version
        packet_data.extend(encode_varint(self.protocol_version));
        // Server address (string: varint length + bytes)
        packet_data.extend(encode_varint(self.server_address.len() as i32));
        packet_data.extend(self.server_address.as_bytes());
        // Server port (unsigned short, big-endian)
        packet_data.extend_from_slice(&self.server_port.to_be_bytes());
        // Next state
        packet_data.extend(encode_varint(self.next_state));

        // Wrap with packet length prefix
        let mut packet = encode_varint(packet_data.len() as i32);
        packet.extend(packet_data);

        packet
    }
}

/// RakNet Unconnected Ping builder
#[derive(Debug, Clone)]
pub struct RakNetPing {
    pub packet_id: u8,
    pub time: u64,
    pub client_guid: u64,
}

impl Default for RakNetPing {
    fn default() -> Self {
        Self {
            packet_id: RAKNET_UNCONNECTED_PING,
            time: 0,
            client_guid: 0x1234567890abcdef,
        }
    }
}

impl RakNetPing {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_time(mut self, time: u64) -> Self {
        self.time = time;
        self
    }

    pub fn with_guid(mut self, guid: u64) -> Self {
        self.client_guid = guid;
        self
    }

    pub fn open_connections(mut self) -> Self {
        self.packet_id = RAKNET_UNCONNECTED_PING_OPEN;
        self
    }

    pub fn build(&self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(33);

        // Packet ID
        packet.push(self.packet_id);
        // Time (8 bytes)
        packet.extend_from_slice(&self.time.to_be_bytes());
        // RakNet magic (16 bytes)
        packet.extend_from_slice(&RAKNET_MAGIC);
        // Client GUID (8 bytes)
        packet.extend_from_slice(&self.client_guid.to_be_bytes());

        packet
    }
}

/// RakNet Open Connection Request 1 builder
#[derive(Debug, Clone)]
pub struct RakNetOpenConnReq1 {
    pub protocol_version: u8,
    pub mtu_size: u16,
}

impl Default for RakNetOpenConnReq1 {
    fn default() -> Self {
        Self {
            protocol_version: 11,
            mtu_size: 1400,
        }
    }
}

impl RakNetOpenConnReq1 {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_protocol(mut self, version: u8) -> Self {
        self.protocol_version = version;
        self
    }

    pub fn with_mtu(mut self, mtu: u16) -> Self {
        self.mtu_size = mtu;
        self
    }

    pub fn build(&self) -> Vec<u8> {
        // Packet structure: ID (1) + Magic (16) + Protocol (1) + MTU padding (variable)
        let padding_size = self.mtu_size.saturating_sub(18) as usize;
        let mut packet = Vec::with_capacity(18 + padding_size);

        // Packet ID
        packet.push(RAKNET_OPEN_CONNECTION_REQUEST_1);
        // RakNet magic
        packet.extend_from_slice(&RAKNET_MAGIC);
        // Protocol version
        packet.push(self.protocol_version);
        // MTU padding (zeros)
        packet.resize(18 + padding_size, 0);

        packet
    }
}

/// RakNet Open Connection Request 2 builder
#[derive(Debug, Clone)]
pub struct RakNetOpenConnReq2 {
    pub server_address: Ipv4Addr,
    pub server_port: u16,
    pub mtu_size: u16,
    pub client_guid: u64,
}

impl Default for RakNetOpenConnReq2 {
    fn default() -> Self {
        Self {
            server_address: Ipv4Addr::new(127, 0, 0, 1),
            server_port: 19132,
            mtu_size: 1400,
            client_guid: 0x1234567890abcdef,
        }
    }
}

impl RakNetOpenConnReq2 {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_mtu(mut self, mtu: u16) -> Self {
        self.mtu_size = mtu;
        self
    }

    pub fn with_guid(mut self, guid: u64) -> Self {
        self.client_guid = guid;
        self
    }

    pub fn build(&self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(34);

        // Packet ID
        packet.push(RAKNET_OPEN_CONNECTION_REQUEST_2);
        // RakNet magic
        packet.extend_from_slice(&RAKNET_MAGIC);
        // Server address (IPv4 format: type + ip + port = 7 bytes)
        packet.push(4); // IPv4 type
        packet.extend_from_slice(&self.server_address.octets());
        packet.extend_from_slice(&self.server_port.to_be_bytes());
        // MTU size
        packet.extend_from_slice(&self.mtu_size.to_be_bytes());
        // Client GUID
        packet.extend_from_slice(&self.client_guid.to_be_bytes());

        packet
    }
}

/// Compute IP header checksum
fn compute_ip_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Sum 16-bit words
    for i in (0..header.len()).step_by(2) {
        if i == 10 {
            continue; // Skip checksum field
        }
        let word = if i + 1 < header.len() {
            ((header[i] as u32) << 8) | (header[i + 1] as u32)
        } else {
            (header[i] as u32) << 8
        };
        sum += word;
    }

    // Fold carries
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // One's complement
    !sum as u16
}

/// Create a complete TCP packet with Ethernet, IP, and TCP headers
pub fn create_tcp_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    flags: u8,
    payload: Vec<u8>,
) -> Vec<u8> {
    let tcp = TcpSegment::new()
        .with_src_port(src_port)
        .with_dst_port(dst_port)
        .with_flags(flags)
        .with_payload(payload)
        .build();

    let ip = Ipv4Packet::new()
        .with_src_ip(src_ip)
        .with_dst_ip(dst_ip)
        .with_protocol(IPPROTO_TCP)
        .with_payload(tcp)
        .build();

    EthernetFrame::new()
        .with_ether_type(ETH_P_IP)
        .with_payload(ip)
        .build()
}

/// Create a complete UDP packet with Ethernet, IP, and UDP headers
pub fn create_udp_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: Vec<u8>,
) -> Vec<u8> {
    let udp = UdpDatagram::new()
        .with_src_port(src_port)
        .with_dst_port(dst_port)
        .with_payload(payload)
        .build();

    let ip = Ipv4Packet::new()
        .with_src_ip(src_ip)
        .with_dst_ip(dst_ip)
        .with_protocol(IPPROTO_UDP)
        .with_payload(udp)
        .build();

    EthernetFrame::new()
        .with_ether_type(ETH_P_IP)
        .with_payload(ip)
        .build()
}

/// Create a Minecraft Java handshake packet
pub fn create_minecraft_handshake_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    protocol_version: i32,
    next_state: i32,
) -> Vec<u8> {
    let handshake = MinecraftHandshake::new()
        .with_protocol(protocol_version)
        .with_next_state(next_state)
        .build();

    create_tcp_packet(
        src_ip,
        dst_ip,
        src_port,
        25565,
        TCP_ACK | TCP_PSH,
        handshake,
    )
}

/// Create a RakNet ping packet
pub fn create_raknet_ping_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    client_guid: u64,
) -> Vec<u8> {
    let ping = RakNetPing::new().with_guid(client_guid).build();

    create_udp_packet(src_ip, dst_ip, src_port, 19132, ping)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_encoding() {
        // Small positive values
        assert_eq!(encode_varint(0), vec![0x00]);
        assert_eq!(encode_varint(1), vec![0x01]);
        assert_eq!(encode_varint(127), vec![0x7f]);

        // Multi-byte values
        assert_eq!(encode_varint(128), vec![0x80, 0x01]);
        assert_eq!(encode_varint(255), vec![0xff, 0x01]);
        assert_eq!(encode_varint(25565), vec![0xdd, 0xc7, 0x01]);
        assert_eq!(encode_varint(765), vec![0xfd, 0x05]);

        // Negative values (two's complement)
        assert_eq!(encode_varint(-1), vec![0xff, 0xff, 0xff, 0xff, 0x0f]);
    }

    #[test]
    fn test_varint_decoding() {
        assert_eq!(decode_varint(&[0x00]), Some((0, 1)));
        assert_eq!(decode_varint(&[0x01]), Some((1, 1)));
        assert_eq!(decode_varint(&[0x7f]), Some((127, 1)));
        assert_eq!(decode_varint(&[0x80, 0x01]), Some((128, 2)));
        assert_eq!(decode_varint(&[0xdd, 0xc7, 0x01]), Some((25565, 3)));
        assert_eq!(decode_varint(&[0xfd, 0x05]), Some((765, 2)));

        // Negative values
        assert_eq!(
            decode_varint(&[0xff, 0xff, 0xff, 0xff, 0x0f]),
            Some((-1, 5))
        );
    }

    #[test]
    fn test_varint_roundtrip() {
        let test_values = [0, 1, 127, 128, 255, 25565, 765, 2097151, -1, -128];

        for &val in &test_values {
            let encoded = encode_varint(val);
            let (decoded, _) = decode_varint(&encoded).unwrap();
            assert_eq!(decoded, val, "Roundtrip failed for {}", val);
        }
    }

    #[test]
    fn test_minecraft_handshake_build() {
        let packet = MinecraftHandshake::new()
            .with_protocol(765)
            .with_address("localhost")
            .with_port(25565)
            .login()
            .build();

        // Verify structure
        let (packet_len, len_bytes) = decode_varint(&packet).unwrap();
        assert!(packet_len > 0);
        assert!(packet.len() == (len_bytes + packet_len as usize));

        // Verify packet ID
        let (packet_id, _) = decode_varint(&packet[len_bytes..]).unwrap();
        assert_eq!(packet_id, 0);
    }

    #[test]
    fn test_raknet_ping_build() {
        let ping = RakNetPing::new().with_guid(0x1234567890abcdef).build();

        assert_eq!(ping.len(), 33);
        assert_eq!(ping[0], RAKNET_UNCONNECTED_PING);
        assert_eq!(&ping[9..25], &RAKNET_MAGIC);
    }

    #[test]
    fn test_raknet_open_conn_req1_build() {
        let req = RakNetOpenConnReq1::new()
            .with_protocol(11)
            .with_mtu(1400)
            .build();

        assert_eq!(req.len(), 1400);
        assert_eq!(req[0], RAKNET_OPEN_CONNECTION_REQUEST_1);
        assert_eq!(&req[1..17], &RAKNET_MAGIC);
        assert_eq!(req[17], 11);
    }

    #[test]
    fn test_tcp_segment_build() {
        let segment = TcpSegment::new()
            .with_src_port(12345)
            .with_dst_port(80)
            .syn()
            .build();

        assert!(segment.len() >= 20);
        // Source port
        assert_eq!(&segment[0..2], &12345u16.to_be_bytes());
        // Destination port
        assert_eq!(&segment[2..4], &80u16.to_be_bytes());
    }

    #[test]
    fn test_udp_datagram_build() {
        let datagram = UdpDatagram::new()
            .with_src_port(12345)
            .with_dst_port(19132)
            .with_payload(vec![1, 2, 3, 4])
            .build();

        assert_eq!(datagram.len(), 12);
        // Source port
        assert_eq!(&datagram[0..2], &12345u16.to_be_bytes());
        // Destination port
        assert_eq!(&datagram[2..4], &19132u16.to_be_bytes());
        // Length
        assert_eq!(&datagram[4..6], &12u16.to_be_bytes());
    }

    #[test]
    fn test_create_tcp_packet() {
        let packet = create_tcp_packet(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 1, 1),
            12345,
            80,
            TCP_SYN,
            vec![],
        );

        // Minimum size: Eth (14) + IP (20) + TCP (20) = 54
        assert!(packet.len() >= 54);
    }
}
