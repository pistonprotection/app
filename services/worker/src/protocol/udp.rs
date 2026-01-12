//! Generic UDP protocol analysis and filtering

use super::{AnalyzerStats, L7Protocol, PacketMeta, ProtocolAnalyzer, Verdict};
use parking_lot::RwLock;
use pistonprotection_common::error::Result;
use tracing::debug;

/// Generic UDP analyzer
pub struct UdpAnalyzer {
    stats: RwLock<AnalyzerStats>,
    /// Maximum packet size
    max_packet_size: usize,
    /// Minimum packet size (to detect amplification)
    min_packet_size: usize,
    /// Enable UDP flood detection
    flood_detection: bool,
}

impl UdpAnalyzer {
    pub fn new() -> Self {
        Self {
            stats: RwLock::new(AnalyzerStats::default()),
            max_packet_size: 65507, // Max UDP payload
            min_packet_size: 1,
            flood_detection: true,
        }
    }

    /// Check for DNS amplification attack patterns
    fn is_dns_amplification(&self, payload: &[u8]) -> bool {
        // DNS responses typically have:
        // - QR bit set (bit 15 of flags)
        // - Response code in flags
        // - Often large answer sections

        if payload.len() < 12 {
            return false;
        }

        // Check DNS header flags
        let flags = u16::from_be_bytes([payload[2], payload[3]]);
        let is_response = (flags & 0x8000) != 0;
        let ancount = u16::from_be_bytes([payload[6], payload[7]]);

        // Large DNS response without matching query is suspicious
        is_response && ancount > 5 && payload.len() > 512
    }

    /// Check for NTP amplification attack patterns
    fn is_ntp_amplification(&self, payload: &[u8]) -> bool {
        // NTP mode 7 (private) responses can be used for amplification
        if payload.len() < 4 {
            return false;
        }

        let version = (payload[0] >> 3) & 0x07;
        let mode = payload[0] & 0x07;

        // Mode 7 is often used in amplification attacks
        mode == 7 && payload.len() > 100
    }

    /// Check for memcached amplification
    fn is_memcached_amplification(&self, payload: &[u8]) -> bool {
        // Memcached responses can be very large
        if payload.len() < 8 {
            return false;
        }

        // Check for memcached binary protocol response
        if payload[0] == 0x81 {
            return payload.len() > 1400;
        }

        // Check for text protocol stats response
        if payload.starts_with(b"STAT ") {
            return payload.len() > 1400;
        }

        false
    }
}

impl ProtocolAnalyzer for UdpAnalyzer {
    fn protocol(&self) -> L7Protocol {
        L7Protocol::GenericUdp
    }

    fn can_handle(&self, meta: &PacketMeta, _payload: &[u8]) -> bool {
        matches!(meta.protocol, super::Protocol::Udp)
    }

    fn analyze(&self, meta: &PacketMeta, payload: &[u8]) -> Result<Verdict> {
        let mut stats = self.stats.write();
        stats.packets_analyzed += 1;
        stats.bytes_analyzed += payload.len() as u64;

        // Check packet size
        if payload.len() > self.max_packet_size {
            debug!(src = %meta.src_ip, size = payload.len(), "UDP packet too large");
            stats.packets_dropped += 1;
            return Ok(Verdict::Drop);
        }

        // Check for amplification attacks
        if self.flood_detection {
            // DNS amplification (port 53)
            if meta.src_port == 53 && self.is_dns_amplification(payload) {
                debug!(src = %meta.src_ip, "DNS amplification detected");
                stats.packets_dropped += 1;
                return Ok(Verdict::Drop);
            }

            // NTP amplification (port 123)
            if meta.src_port == 123 && self.is_ntp_amplification(payload) {
                debug!(src = %meta.src_ip, "NTP amplification detected");
                stats.packets_dropped += 1;
                return Ok(Verdict::Drop);
            }

            // Memcached amplification (port 11211)
            if meta.src_port == 11211 && self.is_memcached_amplification(payload) {
                debug!(src = %meta.src_ip, "Memcached amplification detected");
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

/// Well-known UDP attack vectors
#[derive(Debug, Clone, Copy)]
pub enum UdpAttackType {
    /// DNS amplification
    DnsAmplification,
    /// NTP amplification
    NtpAmplification,
    /// Memcached amplification
    MemcachedAmplification,
    /// SSDP amplification
    SsdpAmplification,
    /// CharGen amplification
    ChargenAmplification,
    /// SNMP amplification
    SnmpAmplification,
    /// Generic UDP flood
    UdpFlood,
}

/// Detect potential UDP attack type based on source port
pub fn detect_attack_type(src_port: u16, payload: &[u8]) -> Option<UdpAttackType> {
    match src_port {
        53 => Some(UdpAttackType::DnsAmplification),
        123 => Some(UdpAttackType::NtpAmplification),
        11211 => Some(UdpAttackType::MemcachedAmplification),
        1900 => Some(UdpAttackType::SsdpAmplification),
        19 => Some(UdpAttackType::ChargenAmplification),
        161 | 162 => Some(UdpAttackType::SnmpAmplification),
        _ => {
            // Check for generic flood (high packet rate handled elsewhere)
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_attack_type() {
        assert!(matches!(
            detect_attack_type(53, &[]),
            Some(UdpAttackType::DnsAmplification)
        ));
        assert!(matches!(
            detect_attack_type(123, &[]),
            Some(UdpAttackType::NtpAmplification)
        ));
        assert!(matches!(
            detect_attack_type(11211, &[]),
            Some(UdpAttackType::MemcachedAmplification)
        ));
        assert!(detect_attack_type(12345, &[]).is_none());
    }
}
