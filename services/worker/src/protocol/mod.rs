//! Protocol analysis and filtering

pub mod http;
pub mod minecraft;
pub mod quic;
pub mod tcp;
pub mod udp;

use pistonprotection_common::error::Result;
use std::net::IpAddr;

/// Packet verdict
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Verdict {
    /// Allow the packet
    Pass,
    /// Drop the packet
    Drop,
    /// Apply rate limiting
    RateLimit,
    /// Challenge required (L7)
    Challenge,
    /// Redirect to different backend
    Redirect,
}

/// Packet metadata extracted during analysis
#[derive(Debug, Clone)]
pub struct PacketMeta {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
    pub l7_protocol: Option<L7Protocol>,
    pub payload_len: usize,
}

/// L4 Protocol
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

impl From<u8> for Protocol {
    fn from(proto: u8) -> Self {
        match proto {
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            1 => Protocol::Icmp,
            other => Protocol::Other(other),
        }
    }
}

/// L7 Protocol
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum L7Protocol {
    Http,
    Http2,
    Http3,
    Quic,
    MinecraftJava,
    MinecraftBedrock,
    GenericTcp,
    GenericUdp,
}

/// Protocol analyzer trait
pub trait ProtocolAnalyzer: Send + Sync {
    /// Get the protocol this analyzer handles
    fn protocol(&self) -> L7Protocol;

    /// Check if this analyzer can handle the packet
    fn can_handle(&self, meta: &PacketMeta, payload: &[u8]) -> bool;

    /// Analyze the packet and return a verdict
    fn analyze(&self, meta: &PacketMeta, payload: &[u8]) -> Result<Verdict>;

    /// Get analysis statistics
    fn stats(&self) -> AnalyzerStats;
}

/// Analyzer statistics
#[derive(Debug, Default, Clone)]
pub struct AnalyzerStats {
    pub packets_analyzed: u64,
    pub packets_passed: u64,
    pub packets_dropped: u64,
    pub packets_challenged: u64,
    pub bytes_analyzed: u64,
}

/// Protocol detection
pub fn detect_protocol(meta: &PacketMeta, payload: &[u8]) -> Option<L7Protocol> {
    match meta.protocol {
        Protocol::Tcp => {
            // Check for Minecraft Java (port 25565 or protocol signature)
            if meta.dst_port == 25565 || minecraft::is_minecraft_java(payload) {
                return Some(L7Protocol::MinecraftJava);
            }

            // Check for HTTP
            if http::is_http(payload) {
                if http::is_http2(payload) {
                    return Some(L7Protocol::Http2);
                }
                return Some(L7Protocol::Http);
            }

            Some(L7Protocol::GenericTcp)
        }
        Protocol::Udp => {
            // Check for Minecraft Bedrock (port 19132 or RakNet signature)
            if meta.dst_port == 19132 || minecraft::is_minecraft_bedrock(payload) {
                return Some(L7Protocol::MinecraftBedrock);
            }

            // Check for QUIC
            if quic::is_quic(payload) {
                // HTTP/3 runs over QUIC
                if meta.dst_port == 443 || meta.dst_port == 8443 {
                    return Some(L7Protocol::Http3);
                }
                return Some(L7Protocol::Quic);
            }

            Some(L7Protocol::GenericUdp)
        }
        _ => None,
    }
}
