//! Generic TCP protocol analysis and filtering

use super::{AnalyzerStats, L7Protocol, PacketMeta, ProtocolAnalyzer, Verdict};
use parking_lot::RwLock;
use pistonprotection_common::error::Result;

/// Generic TCP analyzer for connection rate limiting
pub struct TcpAnalyzer {
    stats: RwLock<AnalyzerStats>,
    /// Maximum SYN packets per second per IP
    max_syn_rate: u32,
    /// Maximum connections per IP
    max_connections_per_ip: u32,
}

impl TcpAnalyzer {
    pub fn new() -> Self {
        Self {
            stats: RwLock::new(AnalyzerStats::default()),
            max_syn_rate: 100,
            max_connections_per_ip: 1000,
        }
    }
}

impl ProtocolAnalyzer for TcpAnalyzer {
    fn protocol(&self) -> L7Protocol {
        L7Protocol::GenericTcp
    }

    fn can_handle(&self, meta: &PacketMeta, _payload: &[u8]) -> bool {
        matches!(meta.protocol, super::Protocol::Tcp)
    }

    fn analyze(&self, _meta: &PacketMeta, payload: &[u8]) -> Result<Verdict> {
        let mut stats = self.stats.write();
        stats.packets_analyzed += 1;
        stats.bytes_analyzed += payload.len() as u64;

        // Generic TCP analysis would check TCP flags, sequence numbers, etc.
        // This is typically handled at the eBPF level for performance

        stats.packets_passed += 1;
        Ok(Verdict::Pass)
    }

    fn stats(&self) -> AnalyzerStats {
        self.stats.read().clone()
    }
}

/// TCP connection state tracking
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TcpState {
    /// Initial state
    Listen,
    /// SYN sent
    SynSent,
    /// SYN received
    SynReceived,
    /// Connection established
    Established,
    /// FIN wait 1
    FinWait1,
    /// FIN wait 2
    FinWait2,
    /// Close wait
    CloseWait,
    /// Closing
    Closing,
    /// Last ACK
    LastAck,
    /// Time wait
    TimeWait,
    /// Closed
    Closed,
}

/// TCP flags
#[derive(Debug, Clone, Copy)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
}

impl TcpFlags {
    /// Parse TCP flags from a byte
    pub fn from_byte(byte: u8) -> Self {
        Self {
            fin: byte & 0x01 != 0,
            syn: byte & 0x02 != 0,
            rst: byte & 0x04 != 0,
            psh: byte & 0x08 != 0,
            ack: byte & 0x10 != 0,
            urg: byte & 0x20 != 0,
            ece: byte & 0x40 != 0,
            cwr: byte & 0x80 != 0,
        }
    }

    /// Check for SYN flood indicators
    pub fn is_syn_only(&self) -> bool {
        self.syn && !self.ack && !self.fin && !self.rst
    }

    /// Check for valid SYN-ACK
    pub fn is_syn_ack(&self) -> bool {
        self.syn && self.ack && !self.fin && !self.rst
    }

    /// Check for valid ACK
    pub fn is_ack_only(&self) -> bool {
        self.ack && !self.syn && !self.fin && !self.rst
    }
}

/// Compute next state based on current state and received flags
pub fn tcp_state_transition(current: TcpState, flags: TcpFlags) -> TcpState {
    match current {
        TcpState::Listen => {
            if flags.syn && !flags.ack {
                TcpState::SynReceived
            } else {
                current
            }
        }
        TcpState::SynSent => {
            if flags.is_syn_ack() {
                TcpState::Established
            } else if flags.syn {
                TcpState::SynReceived
            } else {
                current
            }
        }
        TcpState::SynReceived => {
            if flags.ack {
                TcpState::Established
            } else if flags.rst {
                TcpState::Listen
            } else {
                current
            }
        }
        TcpState::Established => {
            if flags.fin {
                TcpState::CloseWait
            } else if flags.rst {
                TcpState::Closed
            } else {
                current
            }
        }
        TcpState::FinWait1 => {
            if flags.fin && flags.ack {
                TcpState::TimeWait
            } else if flags.fin {
                TcpState::Closing
            } else if flags.ack {
                TcpState::FinWait2
            } else {
                current
            }
        }
        TcpState::FinWait2 => {
            if flags.fin {
                TcpState::TimeWait
            } else {
                current
            }
        }
        TcpState::CloseWait => {
            // Application sends FIN -> LastAck
            // This transition is initiated by local, not packet
            current
        }
        TcpState::Closing => {
            if flags.ack {
                TcpState::TimeWait
            } else {
                current
            }
        }
        TcpState::LastAck => {
            if flags.ack {
                TcpState::Closed
            } else {
                current
            }
        }
        TcpState::TimeWait => {
            // Stays in TimeWait for 2*MSL
            current
        }
        TcpState::Closed => current,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_flags() {
        // SYN packet
        let syn = TcpFlags::from_byte(0x02);
        assert!(syn.syn);
        assert!(!syn.ack);
        assert!(syn.is_syn_only());

        // SYN-ACK packet
        let syn_ack = TcpFlags::from_byte(0x12);
        assert!(syn_ack.syn);
        assert!(syn_ack.ack);
        assert!(syn_ack.is_syn_ack());

        // ACK packet
        let ack = TcpFlags::from_byte(0x10);
        assert!(!ack.syn);
        assert!(ack.ack);
        assert!(ack.is_ack_only());
    }

    #[test]
    fn test_state_transitions() {
        let syn = TcpFlags::from_byte(0x02);
        let syn_ack = TcpFlags::from_byte(0x12);
        let ack = TcpFlags::from_byte(0x10);

        // Normal connection establishment
        assert_eq!(tcp_state_transition(TcpState::Listen, syn), TcpState::SynReceived);
        assert_eq!(tcp_state_transition(TcpState::SynReceived, ack), TcpState::Established);
    }
}
