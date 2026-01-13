//! HAProxy PROXY Protocol implementation (v1 and v2).
//!
//! The PROXY protocol is used to convey connection information (source IP, port, etc.)
//! through proxies and load balancers. This implementation supports both v1 (text-based)
//! and v2 (binary) formats.
//!
//! Reference: https://www.haproxy.org/download/2.4/doc/proxy-protocol.txt

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use thiserror::Error;
use tracing::{debug, trace};

/// PROXY protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProxyProtocolVersion {
    /// No PROXY protocol
    #[default]
    None,
    /// PROXY protocol v1 (text-based)
    V1,
    /// PROXY protocol v2 (binary)
    V2,
}

impl ProxyProtocolVersion {
    /// Create from version number (0 = none, 1 = v1, 2 = v2).
    pub fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::V1,
            2 => Self::V2,
            _ => Self::None,
        }
    }

    /// Convert to version number.
    pub fn to_u8(self) -> u8 {
        match self {
            Self::None => 0,
            Self::V1 => 1,
            Self::V2 => 2,
        }
    }
}

/// PROXY protocol address family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamily {
    /// Unspecified
    Unspec,
    /// IPv4
    Inet,
    /// IPv6
    Inet6,
    /// Unix socket
    Unix,
}

/// PROXY protocol transport protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProtocol {
    /// Unspecified
    Unspec,
    /// TCP (stream)
    Stream,
    /// UDP (datagram)
    Dgram,
}

/// PROXY protocol header information.
#[derive(Debug, Clone)]
pub struct ProxyHeader {
    /// Protocol version
    pub version: ProxyProtocolVersion,
    /// Whether this is a LOCAL command (health check) vs PROXY command
    pub is_local: bool,
    /// Address family
    pub family: AddressFamily,
    /// Transport protocol
    pub protocol: TransportProtocol,
    /// Source address
    pub source: Option<SocketAddr>,
    /// Destination address
    pub destination: Option<SocketAddr>,
    /// TLVs (Type-Length-Value extensions, v2 only)
    pub tlvs: Vec<Tlv>,
}

impl ProxyHeader {
    /// Create a new LOCAL header (for health checks).
    pub fn new_local(version: ProxyProtocolVersion) -> Self {
        Self {
            version,
            is_local: true,
            family: AddressFamily::Unspec,
            protocol: TransportProtocol::Unspec,
            source: None,
            destination: None,
            tlvs: Vec::new(),
        }
    }

    /// Create a new PROXY header for TCP connection.
    pub fn new_tcp(
        version: ProxyProtocolVersion,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> Self {
        let family = match source.ip() {
            IpAddr::V4(_) => AddressFamily::Inet,
            IpAddr::V6(_) => AddressFamily::Inet6,
        };

        Self {
            version,
            is_local: false,
            family,
            protocol: TransportProtocol::Stream,
            source: Some(source),
            destination: Some(destination),
            tlvs: Vec::new(),
        }
    }

    /// Create a new PROXY header for UDP connection.
    pub fn new_udp(
        version: ProxyProtocolVersion,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> Self {
        let family = match source.ip() {
            IpAddr::V4(_) => AddressFamily::Inet,
            IpAddr::V6(_) => AddressFamily::Inet6,
        };

        Self {
            version,
            is_local: false,
            family,
            protocol: TransportProtocol::Dgram,
            source: Some(source),
            destination: Some(destination),
            tlvs: Vec::new(),
        }
    }

    /// Add a TLV (v2 only).
    pub fn add_tlv(&mut self, tlv: Tlv) {
        self.tlvs.push(tlv);
    }

    /// Encode the header to bytes.
    pub fn encode(&self) -> Result<Vec<u8>, ProxyProtocolError> {
        match self.version {
            ProxyProtocolVersion::None => Ok(Vec::new()),
            ProxyProtocolVersion::V1 => self.encode_v1(),
            ProxyProtocolVersion::V2 => self.encode_v2(),
        }
    }

    /// Get the header length.
    pub fn encoded_len(&self) -> usize {
        match self.version {
            ProxyProtocolVersion::None => 0,
            ProxyProtocolVersion::V1 => self.v1_len(),
            ProxyProtocolVersion::V2 => self.v2_len(),
        }
    }

    /// Encode v1 header (text-based).
    fn encode_v1(&self) -> Result<Vec<u8>, ProxyProtocolError> {
        if self.is_local {
            // LOCAL not supported in v1, use minimal UNKNOWN
            return Ok(b"PROXY UNKNOWN\r\n".to_vec());
        }

        let (src, dst) = match (self.source, self.destination) {
            (Some(s), Some(d)) => (s, d),
            _ => return Err(ProxyProtocolError::MissingAddress),
        };

        let proto = match self.family {
            AddressFamily::Inet => "TCP4",
            AddressFamily::Inet6 => "TCP6",
            _ => return Err(ProxyProtocolError::UnsupportedFamily),
        };

        let header = format!(
            "PROXY {} {} {} {} {}\r\n",
            proto,
            src.ip(),
            dst.ip(),
            src.port(),
            dst.port()
        );

        // V1 header max length is 107 bytes
        if header.len() > 107 {
            return Err(ProxyProtocolError::HeaderTooLong);
        }

        Ok(header.into_bytes())
    }

    /// Get v1 header length.
    fn v1_len(&self) -> usize {
        // Estimate based on typical values
        if self.is_local {
            return 15; // "PROXY UNKNOWN\r\n"
        }

        match (self.source, self.destination) {
            (Some(src), Some(_dst)) => {
                let ip_len = match src.ip() {
                    IpAddr::V4(_) => 15 + 15, // max IPv4 len * 2
                    IpAddr::V6(_) => 39 + 39, // max IPv6 len * 2
                };
                // "PROXY TCP4/6 " + ips + " " + ports + "\r\n"
                12 + ip_len + 12 + 2
            }
            _ => 15,
        }
    }

    /// Encode v2 header (binary).
    fn encode_v2(&self) -> Result<Vec<u8>, ProxyProtocolError> {
        let mut buf = Vec::with_capacity(self.v2_len());

        // Signature: 12 bytes
        buf.extend_from_slice(&V2_SIGNATURE);

        // Version and command: 1 byte
        let cmd = if self.is_local { 0x20 } else { 0x21 }; // 0x2X where X is command
        buf.push(cmd);

        // Address family and protocol: 1 byte
        let family_proto = self.encode_family_proto();
        buf.push(family_proto);

        // Address length: 2 bytes (big-endian)
        let addr_len = self.v2_address_len();
        buf.push((addr_len >> 8) as u8);
        buf.push((addr_len & 0xff) as u8);

        // Addresses
        if !self.is_local {
            if let (Some(src), Some(dst)) = (self.source, self.destination) {
                match (src.ip(), dst.ip()) {
                    (IpAddr::V4(src_ip), IpAddr::V4(dst_ip)) => {
                        buf.extend_from_slice(&src_ip.octets());
                        buf.extend_from_slice(&dst_ip.octets());
                        buf.extend_from_slice(&src.port().to_be_bytes());
                        buf.extend_from_slice(&dst.port().to_be_bytes());
                    }
                    (IpAddr::V6(src_ip), IpAddr::V6(dst_ip)) => {
                        buf.extend_from_slice(&src_ip.octets());
                        buf.extend_from_slice(&dst_ip.octets());
                        buf.extend_from_slice(&src.port().to_be_bytes());
                        buf.extend_from_slice(&dst.port().to_be_bytes());
                    }
                    _ => return Err(ProxyProtocolError::AddressFamilyMismatch),
                }
            }
        }

        // TLVs
        for tlv in &self.tlvs {
            buf.push(tlv.type_code);
            let len = tlv.value.len() as u16;
            buf.extend_from_slice(&len.to_be_bytes());
            buf.extend_from_slice(&tlv.value);
        }

        Ok(buf)
    }

    /// Get v2 header length.
    fn v2_len(&self) -> usize {
        16 + self.v2_address_len() as usize
    }

    /// Get v2 address section length.
    fn v2_address_len(&self) -> u16 {
        let base = match self.family {
            AddressFamily::Inet => 12,  // 4+4 bytes IP + 2+2 bytes port
            AddressFamily::Inet6 => 36, // 16+16 bytes IP + 2+2 bytes port
            AddressFamily::Unix => 216, // 108+108 bytes paths
            AddressFamily::Unspec => 0,
        };

        let tlv_len: usize = self.tlvs.iter().map(|t| 3 + t.value.len()).sum();

        base + tlv_len as u16
    }

    /// Encode address family and protocol byte.
    fn encode_family_proto(&self) -> u8 {
        let family = match self.family {
            AddressFamily::Unspec => 0x00,
            AddressFamily::Inet => 0x10,
            AddressFamily::Inet6 => 0x20,
            AddressFamily::Unix => 0x30,
        };

        let proto = match self.protocol {
            TransportProtocol::Unspec => 0x00,
            TransportProtocol::Stream => 0x01,
            TransportProtocol::Dgram => 0x02,
        };

        family | proto
    }
}

/// PROXY protocol v2 signature.
const V2_SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// TLV (Type-Length-Value) for v2 extensions.
#[derive(Debug, Clone)]
pub struct Tlv {
    /// Type code
    pub type_code: u8,
    /// Value
    pub value: Vec<u8>,
}

impl Tlv {
    /// Create a new TLV.
    pub fn new(type_code: u8, value: Vec<u8>) -> Self {
        Self { type_code, value }
    }

    /// Create ALPN TLV (0x01).
    pub fn alpn(value: &str) -> Self {
        Self::new(0x01, value.as_bytes().to_vec())
    }

    /// Create Authority TLV (0x02) - SNI hostname.
    pub fn authority(hostname: &str) -> Self {
        Self::new(0x02, hostname.as_bytes().to_vec())
    }

    /// Create CRC32C TLV (0x03).
    pub fn crc32c(checksum: u32) -> Self {
        Self::new(0x03, checksum.to_be_bytes().to_vec())
    }

    /// Create Unique ID TLV (0x05).
    pub fn unique_id(id: &[u8]) -> Self {
        Self::new(0x05, id.to_vec())
    }

    /// Create SSL TLV (0x20).
    pub fn ssl(flags: u8, version: Option<&str>, cipher: Option<&str>) -> Self {
        let mut value = vec![flags, 0, 0, 0, 0]; // flags + 4 bytes verify result

        if let Some(ver) = version {
            // Sub-TLV for SSL version (0x21)
            value.push(0x21);
            let ver_bytes = ver.as_bytes();
            value.extend_from_slice(&(ver_bytes.len() as u16).to_be_bytes());
            value.extend_from_slice(ver_bytes);
        }

        if let Some(cip) = cipher {
            // Sub-TLV for cipher (0x23)
            value.push(0x23);
            let cip_bytes = cip.as_bytes();
            value.extend_from_slice(&(cip_bytes.len() as u16).to_be_bytes());
            value.extend_from_slice(cip_bytes);
        }

        Self::new(0x20, value)
    }
}

/// Parse a PROXY protocol header from bytes.
pub fn parse_header(data: &[u8]) -> Result<(ProxyHeader, usize), ProxyProtocolError> {
    if data.is_empty() {
        return Err(ProxyProtocolError::InsufficientData);
    }

    // Check for v2 signature
    if data.len() >= 16 && data[..12] == V2_SIGNATURE {
        return parse_v2(data);
    }

    // Check for v1 signature
    if data.starts_with(b"PROXY ") {
        return parse_v1(data);
    }

    Err(ProxyProtocolError::InvalidSignature)
}

/// Parse v1 header.
fn parse_v1(data: &[u8]) -> Result<(ProxyHeader, usize), ProxyProtocolError> {
    // Find CRLF
    let crlf_pos = data
        .windows(2)
        .position(|w| w == b"\r\n")
        .ok_or(ProxyProtocolError::InsufficientData)?;

    if crlf_pos > 105 {
        return Err(ProxyProtocolError::HeaderTooLong);
    }

    let line =
        std::str::from_utf8(&data[6..crlf_pos]).map_err(|_| ProxyProtocolError::InvalidUtf8)?;

    let parts: Vec<&str> = line.split(' ').collect();

    if parts.is_empty() {
        return Err(ProxyProtocolError::InvalidFormat);
    }

    let (family, protocol) = match parts[0] {
        "TCP4" => (AddressFamily::Inet, TransportProtocol::Stream),
        "TCP6" => (AddressFamily::Inet6, TransportProtocol::Stream),
        "UNKNOWN" => {
            return Ok((
                ProxyHeader {
                    version: ProxyProtocolVersion::V1,
                    is_local: true,
                    family: AddressFamily::Unspec,
                    protocol: TransportProtocol::Unspec,
                    source: None,
                    destination: None,
                    tlvs: Vec::new(),
                },
                crlf_pos + 2,
            ));
        }
        _ => return Err(ProxyProtocolError::InvalidFormat),
    };

    if parts.len() != 5 {
        return Err(ProxyProtocolError::InvalidFormat);
    }

    let src_ip: IpAddr = parts[1].parse().map_err(|_| ProxyProtocolError::InvalidAddress)?;
    let dst_ip: IpAddr = parts[2].parse().map_err(|_| ProxyProtocolError::InvalidAddress)?;
    let src_port: u16 = parts[3].parse().map_err(|_| ProxyProtocolError::InvalidPort)?;
    let dst_port: u16 = parts[4].parse().map_err(|_| ProxyProtocolError::InvalidPort)?;

    trace!(
        src = %src_ip,
        dst = %dst_ip,
        src_port = src_port,
        dst_port = dst_port,
        "Parsed v1 PROXY header"
    );

    Ok((
        ProxyHeader {
            version: ProxyProtocolVersion::V1,
            is_local: false,
            family,
            protocol,
            source: Some(SocketAddr::new(src_ip, src_port)),
            destination: Some(SocketAddr::new(dst_ip, dst_port)),
            tlvs: Vec::new(),
        },
        crlf_pos + 2,
    ))
}

/// Parse v2 header.
fn parse_v2(data: &[u8]) -> Result<(ProxyHeader, usize), ProxyProtocolError> {
    if data.len() < 16 {
        return Err(ProxyProtocolError::InsufficientData);
    }

    let ver_cmd = data[12];
    let version = (ver_cmd >> 4) & 0x0f;
    let command = ver_cmd & 0x0f;

    if version != 2 {
        return Err(ProxyProtocolError::InvalidVersion);
    }

    let is_local = match command {
        0 => true,  // LOCAL
        1 => false, // PROXY
        _ => return Err(ProxyProtocolError::InvalidCommand),
    };

    let family_proto = data[13];
    let family = match (family_proto >> 4) & 0x0f {
        0 => AddressFamily::Unspec,
        1 => AddressFamily::Inet,
        2 => AddressFamily::Inet6,
        3 => AddressFamily::Unix,
        _ => return Err(ProxyProtocolError::InvalidFormat),
    };

    let protocol = match family_proto & 0x0f {
        0 => TransportProtocol::Unspec,
        1 => TransportProtocol::Stream,
        2 => TransportProtocol::Dgram,
        _ => return Err(ProxyProtocolError::InvalidFormat),
    };

    let addr_len = u16::from_be_bytes([data[14], data[15]]) as usize;
    let total_len = 16 + addr_len;

    if data.len() < total_len {
        return Err(ProxyProtocolError::InsufficientData);
    }

    let (source, destination) = if is_local {
        (None, None)
    } else {
        parse_v2_addresses(&data[16..16 + addr_len], family)?
    };

    // Parse TLVs if any remaining
    let addr_base_len = match family {
        AddressFamily::Inet => 12,
        AddressFamily::Inet6 => 36,
        AddressFamily::Unix => 216,
        AddressFamily::Unspec => 0,
    };

    let mut tlvs = Vec::new();
    if addr_len > addr_base_len {
        let tlv_data = &data[16 + addr_base_len..16 + addr_len];
        tlvs = parse_tlvs(tlv_data)?;
    }

    debug!(
        src = ?source,
        dst = ?destination,
        is_local = is_local,
        "Parsed v2 PROXY header"
    );

    Ok((
        ProxyHeader {
            version: ProxyProtocolVersion::V2,
            is_local,
            family,
            protocol,
            source,
            destination,
            tlvs,
        },
        total_len,
    ))
}

/// Parse v2 addresses.
fn parse_v2_addresses(
    data: &[u8],
    family: AddressFamily,
) -> Result<(Option<SocketAddr>, Option<SocketAddr>), ProxyProtocolError> {
    match family {
        AddressFamily::Inet => {
            if data.len() < 12 {
                return Err(ProxyProtocolError::InsufficientData);
            }
            let src_ip = Ipv4Addr::new(data[0], data[1], data[2], data[3]);
            let dst_ip = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
            let src_port = u16::from_be_bytes([data[8], data[9]]);
            let dst_port = u16::from_be_bytes([data[10], data[11]]);
            Ok((
                Some(SocketAddr::new(IpAddr::V4(src_ip), src_port)),
                Some(SocketAddr::new(IpAddr::V4(dst_ip), dst_port)),
            ))
        }
        AddressFamily::Inet6 => {
            if data.len() < 36 {
                return Err(ProxyProtocolError::InsufficientData);
            }
            let src_ip = Ipv6Addr::from(<[u8; 16]>::try_from(&data[0..16]).unwrap());
            let dst_ip = Ipv6Addr::from(<[u8; 16]>::try_from(&data[16..32]).unwrap());
            let src_port = u16::from_be_bytes([data[32], data[33]]);
            let dst_port = u16::from_be_bytes([data[34], data[35]]);
            Ok((
                Some(SocketAddr::new(IpAddr::V6(src_ip), src_port)),
                Some(SocketAddr::new(IpAddr::V6(dst_ip), dst_port)),
            ))
        }
        AddressFamily::Unspec | AddressFamily::Unix => Ok((None, None)),
    }
}

/// Parse TLVs.
fn parse_tlvs(data: &[u8]) -> Result<Vec<Tlv>, ProxyProtocolError> {
    let mut tlvs = Vec::new();
    let mut offset = 0;

    while offset + 3 <= data.len() {
        let type_code = data[offset];
        let length = u16::from_be_bytes([data[offset + 1], data[offset + 2]]) as usize;

        if offset + 3 + length > data.len() {
            break;
        }

        let value = data[offset + 3..offset + 3 + length].to_vec();
        tlvs.push(Tlv { type_code, value });

        offset += 3 + length;
    }

    Ok(tlvs)
}

/// PROXY protocol errors.
#[derive(Debug, Error)]
pub enum ProxyProtocolError {
    #[error("Insufficient data for PROXY header")]
    InsufficientData,
    #[error("Invalid PROXY protocol signature")]
    InvalidSignature,
    #[error("Invalid PROXY protocol version")]
    InvalidVersion,
    #[error("Invalid PROXY protocol command")]
    InvalidCommand,
    #[error("Invalid PROXY protocol format")]
    InvalidFormat,
    #[error("Invalid UTF-8 in PROXY header")]
    InvalidUtf8,
    #[error("Invalid IP address")]
    InvalidAddress,
    #[error("Invalid port number")]
    InvalidPort,
    #[error("PROXY header too long")]
    HeaderTooLong,
    #[error("Missing source/destination address")]
    MissingAddress,
    #[error("Unsupported address family")]
    UnsupportedFamily,
    #[error("Address family mismatch between source and destination")]
    AddressFamilyMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_v1_tcp4() {
        let header = ProxyHeader::new_tcp(
            ProxyProtocolVersion::V1,
            "192.168.1.100:12345".parse().unwrap(),
            "10.0.0.1:80".parse().unwrap(),
        );

        let encoded = header.encode().unwrap();
        let expected = b"PROXY TCP4 192.168.1.100 10.0.0.1 12345 80\r\n";
        assert_eq!(encoded, expected);
    }

    #[test]
    fn test_encode_v1_tcp6() {
        let header = ProxyHeader::new_tcp(
            ProxyProtocolVersion::V1,
            "[2001:db8::1]:12345".parse().unwrap(),
            "[2001:db8::2]:80".parse().unwrap(),
        );

        let encoded = header.encode().unwrap();
        let expected = b"PROXY TCP6 2001:db8::1 2001:db8::2 12345 80\r\n";
        assert_eq!(encoded, expected);
    }

    #[test]
    fn test_encode_v2_tcp4() {
        let header = ProxyHeader::new_tcp(
            ProxyProtocolVersion::V2,
            "192.168.1.100:12345".parse().unwrap(),
            "10.0.0.1:80".parse().unwrap(),
        );

        let encoded = header.encode().unwrap();
        assert_eq!(&encoded[..12], &V2_SIGNATURE);
        assert_eq!(encoded[12], 0x21); // PROXY command
        assert_eq!(encoded[13], 0x11); // IPv4 + STREAM
        assert_eq!(encoded.len(), 28); // 16 header + 12 addresses
    }

    #[test]
    fn test_parse_v1_tcp4() {
        let data = b"PROXY TCP4 192.168.1.100 10.0.0.1 12345 80\r\nHello";
        let (header, consumed) = parse_header(data).unwrap();

        assert_eq!(header.version, ProxyProtocolVersion::V1);
        assert!(!header.is_local);
        assert_eq!(header.family, AddressFamily::Inet);
        assert_eq!(header.protocol, TransportProtocol::Stream);
        assert_eq!(
            header.source.unwrap().to_string(),
            "192.168.1.100:12345"
        );
        assert_eq!(header.destination.unwrap().to_string(), "10.0.0.1:80");
        assert_eq!(consumed, 44);
    }

    #[test]
    fn test_parse_v1_unknown() {
        let data = b"PROXY UNKNOWN\r\n";
        let (header, consumed) = parse_header(data).unwrap();

        assert_eq!(header.version, ProxyProtocolVersion::V1);
        assert!(header.is_local);
        assert_eq!(consumed, 15);
    }

    #[test]
    fn test_parse_v2() {
        let header = ProxyHeader::new_tcp(
            ProxyProtocolVersion::V2,
            "192.168.1.100:12345".parse().unwrap(),
            "10.0.0.1:80".parse().unwrap(),
        );

        let encoded = header.encode().unwrap();
        let (parsed, consumed) = parse_header(&encoded).unwrap();

        assert_eq!(parsed.version, ProxyProtocolVersion::V2);
        assert!(!parsed.is_local);
        assert_eq!(parsed.source, header.source);
        assert_eq!(parsed.destination, header.destination);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn test_v2_with_tlv() {
        let mut header = ProxyHeader::new_tcp(
            ProxyProtocolVersion::V2,
            "192.168.1.100:12345".parse().unwrap(),
            "10.0.0.1:80".parse().unwrap(),
        );
        header.add_tlv(Tlv::authority("example.com"));

        let encoded = header.encode().unwrap();
        let (parsed, _) = parse_header(&encoded).unwrap();

        assert_eq!(parsed.tlvs.len(), 1);
        assert_eq!(parsed.tlvs[0].type_code, 0x02);
        assert_eq!(parsed.tlvs[0].value, b"example.com");
    }

    #[test]
    fn test_local_header() {
        let header = ProxyHeader::new_local(ProxyProtocolVersion::V2);
        let encoded = header.encode().unwrap();
        let (parsed, _) = parse_header(&encoded).unwrap();

        assert!(parsed.is_local);
        assert!(parsed.source.is_none());
        assert!(parsed.destination.is_none());
    }
}
