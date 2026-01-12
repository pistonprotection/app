//! Network interface discovery and management

use nix::sys::socket::SockaddrLike;
use pistonprotection_common::error::{Error, Result};
use std::net::IpAddr;
use tracing::debug;

/// Network interface information
#[derive(Debug, Clone)]
pub struct NetworkInterface {
    pub name: String,
    pub index: u32,
    pub mac_address: Option<[u8; 6]>,
    pub ip_address: Option<IpAddr>,
    pub is_up: bool,
    pub is_loopback: bool,
    pub mtu: u32,
}

impl NetworkInterface {
    /// Check if this interface is suitable for XDP
    pub fn supports_xdp(&self) -> bool {
        // Loopback doesn't support XDP well
        if self.is_loopback {
            return false;
        }

        // Interface must be up
        if !self.is_up {
            return false;
        }

        // Skip virtual interfaces (usually)
        let virtual_prefixes = ["veth", "docker", "br-", "virbr", "cni", "flannel"];
        for prefix in &virtual_prefixes {
            if self.name.starts_with(prefix) {
                return false;
            }
        }

        true
    }
}

/// Discover all network interfaces on the system
pub fn discover_interfaces() -> Result<Vec<NetworkInterface>> {
    let mut interfaces = Vec::new();

    // Use nix to get interface list
    let addrs = nix::ifaddrs::getifaddrs()
        .map_err(|e| Error::Internal(format!("Failed to get interfaces: {}", e)))?;

    let mut seen = std::collections::HashSet::new();

    for ifaddr in addrs {
        let name = ifaddr.interface_name.clone();

        // Skip if we've already processed this interface
        if seen.contains(&name) {
            continue;
        }
        seen.insert(name.clone());

        // Get interface index
        let index = nix::net::if_::if_nametoindex(name.as_str())
            .map_err(|e| Error::Internal(format!("Failed to get interface index: {}", e)))?;

        // Get flags
        let flags = ifaddr.flags;
        let is_up = flags.contains(nix::net::if_::InterfaceFlags::IFF_UP);
        let is_loopback = flags.contains(nix::net::if_::InterfaceFlags::IFF_LOOPBACK);

        // Get IP address
        let ip_address = ifaddr.address.and_then(|addr| match addr.family() {
            Some(nix::sys::socket::AddressFamily::Inet) => {
                addr.as_sockaddr_in().map(|sin| IpAddr::V4(sin.ip()))
            }
            Some(nix::sys::socket::AddressFamily::Inet6) => {
                addr.as_sockaddr_in6().map(|sin6| IpAddr::V6(sin6.ip()))
            }
            _ => None,
        });

        // Get MAC address (if available from link layer address)
        let mac_address = None; // Would need additional logic to get MAC

        // Default MTU
        let mtu = 1500; // Would need ioctl to get actual MTU

        let iface = NetworkInterface {
            name,
            index,
            mac_address,
            ip_address,
            is_up,
            is_loopback,
            mtu,
        };

        debug!("Discovered interface: {:?}", iface);
        interfaces.push(iface);
    }

    // Filter to unique interfaces with IP addresses
    let mut unique_interfaces: Vec<NetworkInterface> = Vec::new();
    let mut seen_names = std::collections::HashSet::new();

    for iface in interfaces {
        if !seen_names.contains(&iface.name) {
            seen_names.insert(iface.name.clone());
            unique_interfaces.push(iface);
        }
    }

    Ok(unique_interfaces)
}

/// Get a specific interface by name
pub fn get_interface(name: &str) -> Result<NetworkInterface> {
    let interfaces = discover_interfaces()?;
    interfaces
        .into_iter()
        .find(|i| i.name == name)
        .ok_or_else(|| Error::not_found("Interface", name))
}

/// Get all interfaces suitable for XDP
pub fn get_xdp_interfaces() -> Result<Vec<NetworkInterface>> {
    let interfaces = discover_interfaces()?;
    Ok(interfaces
        .into_iter()
        .filter(|i| i.supports_xdp())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discover_interfaces() {
        let interfaces = discover_interfaces().unwrap();
        // Should at least have loopback
        assert!(!interfaces.is_empty());
    }
}
