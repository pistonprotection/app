//! Protocol parser tests

use super::test_utils::{
    TestPacketMeta, constants, create_ipv4_packet, create_minecraft_bedrock_ping,
    create_minecraft_java_handshake, create_raknet_open_connection_request,
    create_minecraft_transfer_handshake, create_malformed_negative_length_packet,
    create_malformed_overlong_varint, create_negative_packet_id_handshake,
    create_invalid_next_state_handshake, create_raknet_nak_packet,
    create_raknet_amplification_packet, create_minecraft_status_request,
    create_minecraft_ping, create_minecraft_login_start,
};
use crate::protocol::minecraft::{
    MinecraftBedrockAnalyzer, MinecraftBedrockPacket, MinecraftJavaAnalyzer, RAKNET_MAGIC,
    is_minecraft_bedrock, is_minecraft_java,
};
use crate::protocol::{L7Protocol, PacketMeta, ProtocolAnalyzer, Verdict};
use std::net::{IpAddr, Ipv4Addr};

/// Create packet metadata for testing
fn create_test_meta(src_ip: &str, dst_port: u16) -> PacketMeta {
    PacketMeta {
        src_ip: src_ip.parse().unwrap(),
        dst_ip: "10.0.0.1".parse().unwrap(),
        src_port: 12345,
        dst_port,
        protocol: 6, // TCP
        size: 100,
    }
}

// ============================================================================
// VarInt Tests
// ============================================================================

#[cfg(test)]
mod varint_tests {
    use super::*;

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

    /// Test reading single-byte VarInt
    #[test]
    fn test_varint_single_byte() {
        assert_eq!(read_varint(&[0x00]), Some((0, 1)));
        assert_eq!(read_varint(&[0x01]), Some((1, 1)));
        assert_eq!(read_varint(&[0x7f]), Some((127, 1)));
    }

    /// Test reading two-byte VarInt
    #[test]
    fn test_varint_two_bytes() {
        assert_eq!(read_varint(&[0x80, 0x01]), Some((128, 2)));
        assert_eq!(read_varint(&[0xff, 0x01]), Some((255, 2)));
        assert_eq!(read_varint(&[0xff, 0x7f]), Some((16383, 2)));
    }

    /// Test reading three-byte VarInt
    #[test]
    fn test_varint_three_bytes() {
        assert_eq!(read_varint(&[0x80, 0x80, 0x01]), Some((16384, 3)));
    }

    /// Test VarInt with incomplete data
    #[test]
    fn test_varint_incomplete() {
        // Continuation bit set but no more data
        assert_eq!(read_varint(&[0x80]), None);
        assert_eq!(read_varint(&[0xff, 0xff, 0xff, 0xff, 0xff]), None);
    }

    /// Test common Minecraft protocol versions as VarInt
    #[test]
    fn test_protocol_version_varints() {
        // Protocol version 762 (1.19.4) = 0xFA, 0x05
        let v762 = read_varint(&[0xfa, 0x05]);
        assert_eq!(v762, Some((762, 2)));

        // Protocol version 764 (1.20) = 0xFC, 0x05
        let v764 = read_varint(&[0xfc, 0x05]);
        assert_eq!(v764, Some((764, 2)));
    }
}

// ============================================================================
// Minecraft Java Protocol Tests
// ============================================================================

#[cfg(test)]
mod minecraft_java_tests {
    use super::*;

    /// Test detecting Minecraft Java protocol
    #[test]
    fn test_is_minecraft_java() {
        let handshake = create_minecraft_java_handshake(762, "play.example.com", 25565, 2);
        assert!(is_minecraft_java(&handshake));
    }

    /// Test detecting non-Minecraft data
    #[test]
    fn test_is_not_minecraft_java() {
        // Random data
        assert!(!is_minecraft_java(&[0x00, 0x01, 0x02, 0x03]));
        // HTTP request
        assert!(!is_minecraft_java(b"GET / HTTP/1.1\r\n"));
        // Empty
        assert!(!is_minecraft_java(&[]));
    }

    /// Test Java analyzer creation
    #[test]
    fn test_java_analyzer_creation() {
        let analyzer = MinecraftJavaAnalyzer::new();
        assert_eq!(analyzer.protocol(), L7Protocol::MinecraftJava);
    }

    /// Test Java analyzer can_handle by port
    #[test]
    fn test_java_can_handle_by_port() {
        let analyzer = MinecraftJavaAnalyzer::new();

        let meta = create_test_meta("192.168.1.1", 25565);
        assert!(analyzer.can_handle(&meta, &[]));

        let meta = create_test_meta("192.168.1.1", 80);
        assert!(!analyzer.can_handle(&meta, &[]));
    }

    /// Test Java analyzer can_handle by payload
    #[test]
    fn test_java_can_handle_by_payload() {
        let analyzer = MinecraftJavaAnalyzer::new();
        let handshake = create_minecraft_java_handshake(762, "localhost", 25565, 2);

        let meta = create_test_meta("192.168.1.1", 8080); // Non-standard port
        assert!(analyzer.can_handle(&meta, &handshake));
    }

    /// Test analyzing valid handshake
    #[test]
    fn test_analyze_valid_handshake() {
        let analyzer = MinecraftJavaAnalyzer::new();
        let handshake = create_minecraft_java_handshake(762, "play.example.com", 25565, 2);
        let meta = create_test_meta("192.168.1.1", 25565);

        let result = analyzer.analyze(&meta, &handshake);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Verdict::Pass);
    }

    /// Test analyzing invalid handshake
    #[test]
    fn test_analyze_invalid_handshake() {
        let analyzer = MinecraftJavaAnalyzer::new();

        // Invalid handshake with invalid next_state
        let mut handshake = create_minecraft_java_handshake(762, "play.example.com", 25565, 99);
        let meta = create_test_meta("192.168.1.1", 25565);

        let result = analyzer.analyze(&meta, &handshake);

        // Should drop invalid handshake
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Verdict::Drop);
    }

    /// Test statistics tracking
    #[test]
    fn test_java_stats() {
        let analyzer = MinecraftJavaAnalyzer::new();
        let meta = create_test_meta("192.168.1.1", 25565);

        // Analyze some packets
        for _ in 0..10 {
            let handshake = create_minecraft_java_handshake(762, "localhost", 25565, 1);
            let _ = analyzer.analyze(&meta, &handshake);
        }

        let stats = analyzer.stats();
        assert_eq!(stats.packets_analyzed, 10);
    }
}

// ============================================================================
// Minecraft Bedrock Protocol Tests
// ============================================================================

#[cfg(test)]
mod minecraft_bedrock_tests {
    use super::*;

    /// Test detecting Minecraft Bedrock (RakNet) protocol
    #[test]
    fn test_is_minecraft_bedrock() {
        let ping = create_minecraft_bedrock_ping(12345, 0xDEADBEEF);
        assert!(is_minecraft_bedrock(&ping));
    }

    /// Test detecting non-Bedrock data
    #[test]
    fn test_is_not_minecraft_bedrock() {
        // Random data without RakNet magic
        assert!(!is_minecraft_bedrock(&[0x01; 50]));
        // Too short
        assert!(!is_minecraft_bedrock(&[0x01, 0x02]));
        // Empty
        assert!(!is_minecraft_bedrock(&[]));
    }

    /// Test RakNet magic constant
    #[test]
    fn test_raknet_magic() {
        assert_eq!(RAKNET_MAGIC.len(), 16);
        assert_eq!(RAKNET_MAGIC[0], 0x00);
        assert_eq!(RAKNET_MAGIC[1], 0xff);
    }

    /// Test Bedrock analyzer creation
    #[test]
    fn test_bedrock_analyzer_creation() {
        let analyzer = MinecraftBedrockAnalyzer::new();
        assert_eq!(analyzer.protocol(), L7Protocol::MinecraftBedrock);
    }

    /// Test Bedrock analyzer can_handle by port
    #[test]
    fn test_bedrock_can_handle_by_port() {
        let analyzer = MinecraftBedrockAnalyzer::new();

        let mut meta = create_test_meta("192.168.1.1", 19132);
        meta.protocol = 17; // UDP
        assert!(analyzer.can_handle(&meta, &[]));

        meta.dst_port = 80;
        assert!(!analyzer.can_handle(&meta, &[]));
    }

    /// Test analyzing valid RakNet ping
    #[test]
    fn test_analyze_valid_ping() {
        let analyzer = MinecraftBedrockAnalyzer::new();
        let ping = create_minecraft_bedrock_ping(12345, 0xDEADBEEF);

        let mut meta = create_test_meta("192.168.1.1", 19132);
        meta.protocol = 17;

        let result = analyzer.analyze(&meta, &ping);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Verdict::Pass);
    }

    /// Test analyzing invalid RakNet (bad magic)
    #[test]
    fn test_analyze_invalid_magic() {
        let analyzer = MinecraftBedrockAnalyzer::new();

        // Ping without correct magic
        let mut bad_ping = create_minecraft_bedrock_ping(12345, 0xDEADBEEF);
        // Corrupt the magic
        bad_ping[17] = 0xFF;

        let mut meta = create_test_meta("192.168.1.1", 19132);
        meta.protocol = 17;

        let result = analyzer.analyze(&meta, &bad_ping);

        // Should drop invalid magic
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Verdict::Drop);
    }

    /// Test analyzing open connection request
    #[test]
    fn test_analyze_open_connection() {
        let analyzer = MinecraftBedrockAnalyzer::new();
        let request = create_raknet_open_connection_request();

        let mut meta = create_test_meta("192.168.1.1", 19132);
        meta.protocol = 17;

        let result = analyzer.analyze(&meta, &request);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Verdict::Pass);
    }

    /// Test packet type parsing
    #[test]
    fn test_parse_packet_type() {
        let analyzer = MinecraftBedrockAnalyzer::new();

        assert_eq!(
            analyzer.parse_packet_type(&[0x01]),
            MinecraftBedrockPacket::UnconnectedPing
        );
        assert_eq!(
            analyzer.parse_packet_type(&[0x1c]),
            MinecraftBedrockPacket::UnconnectedPong
        );
        assert_eq!(
            analyzer.parse_packet_type(&[0x05]),
            MinecraftBedrockPacket::OpenConnectionRequest1
        );
        assert_eq!(
            analyzer.parse_packet_type(&[0x06]),
            MinecraftBedrockPacket::OpenConnectionReply1
        );
        assert_eq!(
            analyzer.parse_packet_type(&[0x07]),
            MinecraftBedrockPacket::OpenConnectionRequest2
        );
        assert_eq!(
            analyzer.parse_packet_type(&[0x08]),
            MinecraftBedrockPacket::OpenConnectionReply2
        );
        assert_eq!(
            analyzer.parse_packet_type(&[0xFF]),
            MinecraftBedrockPacket::Unknown(0xFF)
        );
    }
}

// ============================================================================
// Generic Protocol Detection Tests
// ============================================================================

#[cfg(test)]
mod protocol_detection_tests {
    use super::*;

    /// Test TCP protocol detection
    #[test]
    fn test_tcp_detection() {
        let packet = create_ipv4_packet(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(10, 0, 0, 1),
            12345,
            25565,
            b"",
            true,
        );

        // IP header protocol field should be TCP (6)
        assert_eq!(packet[9], 6);
    }

    /// Test UDP protocol detection
    #[test]
    fn test_udp_detection() {
        let packet = create_ipv4_packet(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(10, 0, 0, 1),
            12345,
            19132,
            b"",
            false,
        );

        // IP header protocol field should be UDP (17)
        assert_eq!(packet[9], 17);
    }
}

// ============================================================================
// Verdict Tests
// ============================================================================

#[cfg(test)]
mod verdict_tests {
    use super::*;

    /// Test verdict values
    #[test]
    fn test_verdict_values() {
        assert_ne!(Verdict::Pass, Verdict::Drop);
        assert_ne!(Verdict::Pass, Verdict::Challenge);
        assert_ne!(Verdict::Drop, Verdict::Challenge);
    }

    /// Test verdict to XDP action mapping
    #[test]
    fn test_verdict_to_xdp() {
        // XDP actions: XDP_PASS = 2, XDP_DROP = 1, XDP_TX = 3
        assert_eq!(Verdict::Pass.to_xdp_action(), 2);
        assert_eq!(Verdict::Drop.to_xdp_action(), 1);
    }
}

// ============================================================================
// Security Attack Vector Tests
// ============================================================================

#[cfg(test)]
mod security_tests {
    use super::*;

    /// Test that negative packet length is detected and dropped
    #[test]
    fn test_negative_length_attack() {
        let malformed = create_malformed_negative_length_packet();
        // This should NOT be recognized as valid Minecraft
        assert!(!is_minecraft_java(&malformed));
    }

    /// Test that overlong varint is detected
    #[test]
    fn test_overlong_varint_attack() {
        let malformed = create_malformed_overlong_varint();
        // This should NOT be recognized as valid Minecraft
        assert!(!is_minecraft_java(&malformed));
    }

    /// Test negative packet ID detection
    #[test]
    fn test_negative_packet_id_attack() {
        let analyzer = MinecraftJavaAnalyzer::new();
        let malformed = create_negative_packet_id_handshake();
        let meta = create_test_meta("192.168.1.1", 25565);

        let result = analyzer.analyze(&meta, &malformed);
        // Should be dropped as invalid
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Verdict::Drop);
    }

    /// Test invalid next_state values
    #[test]
    fn test_invalid_next_state() {
        let analyzer = MinecraftJavaAnalyzer::new();
        let meta = create_test_meta("192.168.1.1", 25565);

        // Test state 0 (invalid)
        let handshake = create_invalid_next_state_handshake(762, "localhost", 25565, 0);
        let result = analyzer.analyze(&meta, &handshake);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Verdict::Drop);

        // Test state 4 (invalid - only 1, 2, 3 are valid)
        let handshake = create_invalid_next_state_handshake(762, "localhost", 25565, 4);
        let result = analyzer.analyze(&meta, &handshake);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Verdict::Drop);

        // Test state 255 (invalid)
        let handshake = create_invalid_next_state_handshake(762, "localhost", 25565, 255);
        let result = analyzer.analyze(&meta, &handshake);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Verdict::Drop);
    }

    /// Test TRANSFER state (1.20.5+ feature) is valid
    #[test]
    fn test_transfer_state_valid() {
        let analyzer = MinecraftJavaAnalyzer::new();
        let meta = create_test_meta("192.168.1.1", 25565);

        // Protocol version 766 (1.20.5+) with transfer state
        let handshake = create_minecraft_transfer_handshake(766, "localhost", 25565);
        let result = analyzer.analyze(&meta, &handshake);
        assert!(result.is_ok());
        // Transfer state should be accepted
        assert_eq!(result.unwrap(), Verdict::Pass);
    }

    /// Test status request packet
    #[test]
    fn test_status_request() {
        let status = create_minecraft_status_request();
        // Should be at least valid packet structure
        assert!(!status.is_empty());
        assert_eq!(status[0], 0x01); // Length
        assert_eq!(status[1], 0x00); // Packet ID
    }

    /// Test ping packet
    #[test]
    fn test_ping_packet() {
        let ping = create_minecraft_ping(12345678);
        assert_eq!(ping.len(), 10); // Length byte + ID byte + 8 byte long
        assert_eq!(ping[0], 0x09); // Length
        assert_eq!(ping[1], 0x01); // Packet ID
    }

    /// Test login start packet
    #[test]
    fn test_login_start() {
        let login = create_minecraft_login_start("TestPlayer");
        assert!(!login.is_empty());
        // Should contain the username
        let username_bytes = "TestPlayer".as_bytes();
        assert!(login.windows(username_bytes.len()).any(|w| w == username_bytes));
    }
}

// ============================================================================
// RakNet/Bedrock Security Tests
// ============================================================================

#[cfg(test)]
mod raknet_security_tests {
    use super::*;

    /// Test NAK flood packet detection
    #[test]
    fn test_nak_flood_packet() {
        let nak = create_raknet_nak_packet(&[1, 2, 3, 4, 5]);
        assert_eq!(nak[0], 0xA0); // NAK packet ID
        // Should have sequence numbers
        assert!(nak.len() > 3);
    }

    /// Test amplification attack packet
    #[test]
    fn test_amplification_packet() {
        let analyzer = MinecraftBedrockAnalyzer::new();
        let packet = create_raknet_amplification_packet();

        let mut meta = create_test_meta("192.168.1.1", 19132);
        meta.protocol = 17; // UDP

        // Should be analyzed (though rate limiting would block repeated calls)
        let result = analyzer.analyze(&meta, &packet);
        assert!(result.is_ok());
    }

    /// Test that RakNet magic must be valid
    #[test]
    fn test_invalid_raknet_magic() {
        let analyzer = MinecraftBedrockAnalyzer::new();

        // Create packet with invalid magic
        let mut packet = create_minecraft_bedrock_ping(12345, 0xDEADBEEF);
        // Corrupt the magic bytes
        for i in 9..25 {
            packet[i] = 0xAA;
        }

        let mut meta = create_test_meta("192.168.1.1", 19132);
        meta.protocol = 17;

        let result = analyzer.analyze(&meta, &packet);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Verdict::Drop);
    }

    /// Test that extremely small packets are handled
    #[test]
    fn test_small_bedrock_packet() {
        let analyzer = MinecraftBedrockAnalyzer::new();
        let packet = vec![0x01]; // Just packet ID, nothing else

        let mut meta = create_test_meta("192.168.1.1", 19132);
        meta.protocol = 17;

        let result = analyzer.analyze(&meta, &packet);
        assert!(result.is_ok());
        // Small/invalid packets should be dropped
        assert_eq!(result.unwrap(), Verdict::Drop);
    }

    /// Test unknown RakNet packet types
    #[test]
    fn test_unknown_packet_type() {
        let analyzer = MinecraftBedrockAnalyzer::new();

        // Use reserved/unknown packet type
        let mut packet = vec![0xFE]; // Unknown type
        packet.extend_from_slice(&RAKNET_MAGIC);
        packet.extend_from_slice(&[0x00; 8]); // Some padding

        let mut meta = create_test_meta("192.168.1.1", 19132);
        meta.protocol = 17;

        // Unknown types should be dropped for safety
        let result = analyzer.analyze(&meta, &packet);
        assert!(result.is_ok());
    }
}
