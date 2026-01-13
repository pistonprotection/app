//! QUIC protocol analysis and filtering

use super::{AnalyzerStats, L7Protocol, PacketMeta, ProtocolAnalyzer, Verdict};
use parking_lot::RwLock;
use pistonprotection_common::error::Result;
use tracing::debug;

/// QUIC long header packet types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum QuicLongHeaderType {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
}

/// QUIC packet type
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum QuicPacketType {
    /// Long header packet
    Long(QuicLongHeaderType),
    /// Short header packet (1-RTT)
    Short,
    /// Version negotiation
    VersionNegotiation,
    /// Unknown
    Unknown,
}

/// QUIC version constants
pub mod versions {
    pub const QUIC_V1: u32 = 0x00000001;
    pub const QUIC_V2: u32 = 0x6b3343cf;
    pub const QUIC_DRAFT_29: u32 = 0xff00001d;
}

/// Check if payload is QUIC protocol
pub fn is_quic(payload: &[u8]) -> bool {
    if payload.len() < 5 {
        return false;
    }

    let first_byte = payload[0];

    // Check for long header (bit 7 set)
    if first_byte & 0x80 != 0 {
        // Long header format
        // Check for valid form bit (bit 6 should be set for QUIC v1+)
        if first_byte & 0x40 == 0 {
            // Could be version negotiation
            return true;
        }

        // Read version
        let version = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);

        // Check for known QUIC versions
        matches!(
            version,
            versions::QUIC_V1 | versions::QUIC_V2 | 0 | 0xff000000..=0xffffffff
        )
    } else {
        // Short header - harder to detect
        // Check if it could be a valid short header
        // Fixed bit (bit 6) should be set
        first_byte & 0x40 != 0
    }
}

/// Parse QUIC packet type from first byte
pub fn parse_packet_type(payload: &[u8]) -> QuicPacketType {
    if payload.is_empty() {
        return QuicPacketType::Unknown;
    }

    let first_byte = payload[0];

    if first_byte & 0x80 != 0 {
        // Long header
        if payload.len() < 5 {
            return QuicPacketType::Unknown;
        }

        let version = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);

        if version == 0 {
            return QuicPacketType::VersionNegotiation;
        }

        // Extract packet type from bits 4-5
        let packet_type = (first_byte & 0x30) >> 4;

        let long_type = match packet_type {
            0x00 => QuicLongHeaderType::Initial,
            0x01 => QuicLongHeaderType::ZeroRtt,
            0x02 => QuicLongHeaderType::Handshake,
            0x03 => QuicLongHeaderType::Retry,
            _ => return QuicPacketType::Unknown,
        };

        QuicPacketType::Long(long_type)
    } else {
        // Short header
        QuicPacketType::Short
    }
}

/// Extract QUIC version from long header packet
pub fn get_version(payload: &[u8]) -> Option<u32> {
    if payload.len() < 5 {
        return None;
    }

    if payload[0] & 0x80 == 0 {
        return None; // Short header, no version field
    }

    Some(u32::from_be_bytes([
        payload[1], payload[2], payload[3], payload[4],
    ]))
}

/// Get connection ID lengths from initial packet
pub fn get_connection_id_lengths(payload: &[u8]) -> Option<(u8, u8)> {
    if payload.len() < 6 {
        return None;
    }

    if payload[0] & 0x80 == 0 {
        return None; // Short header
    }

    let dcid_len = payload[5];

    if payload.len() < 6 + dcid_len as usize + 1 {
        return None;
    }

    let scid_len = payload[6 + dcid_len as usize];

    Some((dcid_len, scid_len))
}

/// QUIC protocol analyzer
pub struct QuicAnalyzer {
    stats: RwLock<AnalyzerStats>,
    /// Allowed QUIC versions
    allowed_versions: Vec<u32>,
    /// Maximum connection ID length
    max_cid_length: u8,
    /// Require valid initial packet structure
    validate_initial: bool,
}

impl QuicAnalyzer {
    pub fn new() -> Self {
        Self {
            stats: RwLock::new(AnalyzerStats::default()),
            allowed_versions: vec![versions::QUIC_V1, versions::QUIC_V2],
            max_cid_length: 20,
            validate_initial: true,
        }
    }

    /// Validate QUIC initial packet
    fn validate_initial(&self, payload: &[u8]) -> bool {
        // Check minimum size
        if payload.len() < 1200 {
            // Initial packets should be padded to at least 1200 bytes
            return false;
        }

        // Check version
        if let Some(version) = get_version(payload) {
            if version != 0 && !self.allowed_versions.contains(&version) {
                return false;
            }
        }

        // Check connection ID lengths
        if let Some((dcid_len, scid_len)) = get_connection_id_lengths(payload) {
            if dcid_len > self.max_cid_length || scid_len > self.max_cid_length {
                return false;
            }
        }

        true
    }
}

impl ProtocolAnalyzer for QuicAnalyzer {
    fn protocol(&self) -> L7Protocol {
        L7Protocol::Quic
    }

    fn can_handle(&self, _meta: &PacketMeta, payload: &[u8]) -> bool {
        is_quic(payload)
    }

    fn analyze(&self, meta: &PacketMeta, payload: &[u8]) -> Result<Verdict> {
        let mut stats = self.stats.write();
        stats.packets_analyzed += 1;
        stats.bytes_analyzed += payload.len() as u64;

        let packet_type = parse_packet_type(payload);

        match packet_type {
            QuicPacketType::Long(QuicLongHeaderType::Initial) => {
                if self.validate_initial && !self.validate_initial(payload) {
                    debug!(src = %meta.src_ip, "Invalid QUIC initial packet");
                    stats.packets_dropped += 1;
                    return Ok(Verdict::Drop);
                }
            }
            QuicPacketType::VersionNegotiation => {
                // Version negotiation packets are always allowed
            }
            QuicPacketType::Unknown => {
                debug!(src = %meta.src_ip, "Unknown QUIC packet type");
                stats.packets_dropped += 1;
                return Ok(Verdict::Drop);
            }
            _ => {}
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
    fn test_is_quic() {
        // Valid QUIC v1 initial packet header
        let mut initial = vec![0u8; 1200];
        initial[0] = 0xc0; // Long header, Initial type
        initial[1..5].copy_from_slice(&versions::QUIC_V1.to_be_bytes());
        initial[5] = 8; // DCID length
        initial[14] = 8; // SCID length

        assert!(is_quic(&initial));
    }

    #[test]
    fn test_parse_packet_type() {
        // Initial packet
        let mut initial = vec![0u8; 10];
        initial[0] = 0xc0;
        initial[1..5].copy_from_slice(&versions::QUIC_V1.to_be_bytes());

        assert_eq!(
            parse_packet_type(&initial),
            QuicPacketType::Long(QuicLongHeaderType::Initial)
        );

        // Handshake packet
        let mut handshake = vec![0u8; 10];
        handshake[0] = 0xe0; // 0xc0 | (0x02 << 4)
        handshake[1..5].copy_from_slice(&versions::QUIC_V1.to_be_bytes());

        assert_eq!(
            parse_packet_type(&handshake),
            QuicPacketType::Long(QuicLongHeaderType::Handshake)
        );
    }

    #[test]
    fn test_version_negotiation() {
        // Version negotiation has version = 0
        let mut vn = vec![0u8; 10];
        vn[0] = 0x80;
        vn[1..5].copy_from_slice(&[0, 0, 0, 0]);

        assert_eq!(parse_packet_type(&vn), QuicPacketType::VersionNegotiation);
    }
}
