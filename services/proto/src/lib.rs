//! PistonProtection Protocol Buffer Definitions
//!
//! This crate contains all the protocol buffer definitions for inter-service
//! communication in the PistonProtection platform.

#![allow(clippy::derive_partial_eq_without_eq)]
#![allow(clippy::large_enum_variant)]

pub mod common {
    include!("generated/pistonprotection.common.rs");
}

pub mod filter {
    include!("generated/pistonprotection.filter.rs");
}

pub mod backend {
    include!("generated/pistonprotection.backend.rs");
}

pub mod metrics {
    include!("generated/pistonprotection.metrics.rs");
}

pub mod auth {
    include!("generated/pistonprotection.auth.rs");
}

pub mod worker {
    include!("generated/pistonprotection.worker.rs");
}

/// File descriptor set for gRPC reflection
pub const FILE_DESCRIPTOR_SET: &[u8] = include_bytes!("generated/descriptor.bin");

// Re-export commonly used types
pub use common::{
    Action, HealthStatus, IpAddress, IpNetwork, L7Protocol, Pagination, PaginationInfo, PortRange,
    Protocol, RateLimit, Timestamp, Uuid,
};

// Conversion implementations
impl From<std::net::IpAddr> for IpAddress {
    fn from(addr: std::net::IpAddr) -> Self {
        match addr {
            std::net::IpAddr::V4(v4) => IpAddress {
                address: Some(common::ip_address::Address::Ipv4(u32::from(v4))),
            },
            std::net::IpAddr::V6(v6) => IpAddress {
                address: Some(common::ip_address::Address::Ipv6(v6.octets().to_vec())),
            },
        }
    }
}

impl TryFrom<&IpAddress> for std::net::IpAddr {
    type Error = &'static str;

    fn try_from(addr: &IpAddress) -> Result<Self, Self::Error> {
        match &addr.address {
            Some(common::ip_address::Address::Ipv4(v4)) => {
                Ok(std::net::IpAddr::V4(std::net::Ipv4Addr::from(*v4)))
            }
            Some(common::ip_address::Address::Ipv6(v6)) => {
                let bytes: [u8; 16] = v6
                    .as_slice()
                    .try_into()
                    .map_err(|_| "Invalid IPv6 address length")?;
                Ok(std::net::IpAddr::V6(std::net::Ipv6Addr::from(bytes)))
            }
            None => Err("No address specified"),
        }
    }
}

impl From<chrono::DateTime<chrono::Utc>> for Timestamp {
    fn from(dt: chrono::DateTime<chrono::Utc>) -> Self {
        Timestamp {
            seconds: dt.timestamp(),
            nanos: dt.timestamp_subsec_nanos() as i32,
        }
    }
}

impl From<&Timestamp> for chrono::DateTime<chrono::Utc> {
    fn from(ts: &Timestamp) -> Self {
        chrono::DateTime::from_timestamp(ts.seconds, ts.nanos as u32)
            .unwrap_or_else(chrono::Utc::now)
    }
}

impl From<uuid::Uuid> for Uuid {
    fn from(id: uuid::Uuid) -> Self {
        Uuid {
            value: id.to_string(),
        }
    }
}

impl TryFrom<&Uuid> for uuid::Uuid {
    type Error = uuid::Error;

    fn try_from(id: &Uuid) -> Result<Self, Self::Error> {
        uuid::Uuid::parse_str(&id.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_address_conversion() {
        let ipv4 = std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1));
        let proto_addr: IpAddress = ipv4.into();
        let back: std::net::IpAddr = (&proto_addr).try_into().unwrap();
        assert_eq!(ipv4, back);

        let ipv6 = std::net::IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let proto_addr: IpAddress = ipv6.into();
        let back: std::net::IpAddr = (&proto_addr).try_into().unwrap();
        assert_eq!(ipv6, back);
    }

    #[test]
    fn test_timestamp_conversion() {
        let now = chrono::Utc::now();
        let ts: Timestamp = now.into();
        let back: chrono::DateTime<chrono::Utc> = (&ts).into();

        // Compare with millisecond precision (nanos may differ slightly)
        assert_eq!(
            now.timestamp_millis(),
            back.timestamp_millis(),
            "Timestamps should match to millisecond precision"
        );
    }
}
