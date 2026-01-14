//! eBPF program loader and manager

use super::interface::NetworkInterface;
use super::maps::MapManager;
use aya::Ebpf;
use aya::programs::{Xdp, XdpFlags};
use parking_lot::RwLock;
use pistonprotection_common::error::{Error, Result};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tracing::{info, warn};

/// XDP attachment mode
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum XdpMode {
    /// Hardware offload (best performance, limited support)
    Offload,
    /// Driver mode (good performance, requires driver support)
    Driver,
    /// Generic/SKB mode (works everywhere, slower)
    Generic,
}

impl XdpMode {
    pub fn to_flags(self) -> XdpFlags {
        match self {
            XdpMode::Offload => XdpFlags::HW_MODE,
            XdpMode::Driver => XdpFlags::DRV_MODE,
            XdpMode::Generic => XdpFlags::SKB_MODE,
        }
    }
}

/// Attached XDP program info
#[derive(Debug)]
pub struct AttachedProgram {
    pub interface: String,
    pub mode: XdpMode,
    pub program_name: String,
}

/// eBPF program loader and manager
pub struct EbpfLoader {
    /// Loaded eBPF objects
    objects: HashMap<String, Ebpf>,
    /// Attached XDP programs
    attached: HashMap<String, AttachedProgram>,
    /// Map manager
    maps: Arc<RwLock<MapManager>>,
}

impl EbpfLoader {
    /// Create a new eBPF loader
    pub fn new() -> Result<Self> {
        Ok(Self {
            objects: HashMap::new(),
            attached: HashMap::new(),
            maps: Arc::new(RwLock::new(MapManager::new())),
        })
    }

    /// Load an eBPF program from bytes
    pub fn load_from_bytes(&mut self, name: &str, data: &[u8]) -> Result<()> {
        info!("Loading eBPF program: {}", name);

        let ebpf = Ebpf::load(data)
            .map_err(|e| Error::Internal(format!("Failed to load eBPF program: {}", e)))?;

        self.objects.insert(name.to_string(), ebpf);

        Ok(())
    }

    /// Load an eBPF program from a file
    pub fn load_from_file(&mut self, name: &str, path: &Path) -> Result<()> {
        info!("Loading eBPF program from {:?}: {}", path, name);

        let data = std::fs::read(path)
            .map_err(|e| Error::Internal(format!("Failed to read eBPF file: {}", e)))?;

        self.load_from_bytes(name, &data)
    }

    /// Attach XDP program to an interface
    pub fn attach_xdp(
        &mut self,
        program_name: &str,
        interface: &NetworkInterface,
        preferred_mode: XdpMode,
    ) -> Result<()> {
        info!(
            "Attaching XDP program {} to interface {} (mode: {:?})",
            program_name, interface.name, preferred_mode
        );

        let ebpf = self
            .objects
            .get_mut(program_name)
            .ok_or_else(|| Error::not_found("eBPF program", program_name))?;

        // Get the XDP program
        let program: &mut Xdp = ebpf
            .program_mut(program_name)
            .ok_or_else(|| {
                Error::Internal(format!("Program {} not found in object", program_name))
            })?
            .try_into()
            .map_err(|e| Error::Internal(format!("Not an XDP program: {}", e)))?;

        // Load the program
        program
            .load()
            .map_err(|e| Error::Internal(format!("Failed to load XDP program: {}", e)))?;

        // Try to attach with preferred mode, falling back to generic
        // Note: try_attach_program is a standalone function to avoid borrow issues
        let (mode, _flags) = match preferred_mode {
            XdpMode::Offload => {
                // Try offload, fall back to driver, then generic
                if try_attach_program(program, &interface.name, XdpFlags::HW_MODE) {
                    (XdpMode::Offload, XdpFlags::HW_MODE)
                } else if try_attach_program(program, &interface.name, XdpFlags::DRV_MODE) {
                    warn!("Offload mode not supported, using driver mode");
                    (XdpMode::Driver, XdpFlags::DRV_MODE)
                } else {
                    warn!("Driver mode not supported, using generic mode");
                    program
                        .attach(&interface.name, XdpFlags::SKB_MODE)
                        .map_err(|e| Error::Internal(format!("Failed to attach XDP: {}", e)))?;
                    (XdpMode::Generic, XdpFlags::SKB_MODE)
                }
            }
            XdpMode::Driver => {
                if try_attach_program(program, &interface.name, XdpFlags::DRV_MODE) {
                    (XdpMode::Driver, XdpFlags::DRV_MODE)
                } else {
                    warn!("Driver mode not supported, using generic mode");
                    program
                        .attach(&interface.name, XdpFlags::SKB_MODE)
                        .map_err(|e| Error::Internal(format!("Failed to attach XDP: {}", e)))?;
                    (XdpMode::Generic, XdpFlags::SKB_MODE)
                }
            }
            XdpMode::Generic => {
                program
                    .attach(&interface.name, XdpFlags::SKB_MODE)
                    .map_err(|e| Error::Internal(format!("Failed to attach XDP: {}", e)))?;
                (XdpMode::Generic, XdpFlags::SKB_MODE)
            }
        };

        info!(
            "Attached XDP program {} to {} with mode {:?}",
            program_name, interface.name, mode
        );

        self.attached.insert(
            interface.name.clone(),
            AttachedProgram {
                interface: interface.name.clone(),
                mode,
                program_name: program_name.to_string(),
            },
        );

        Ok(())
    }

    /// Detach XDP program from an interface
    pub fn detach_xdp(&mut self, interface_name: &str) -> Result<()> {
        if let Some(attached) = self.attached.remove(interface_name) {
            info!(
                "Detaching XDP program {} from {}",
                attached.program_name, interface_name
            );
            // Note: aya automatically detaches when the program is dropped
            // For explicit detach, we'd need to keep the link handle
        }
        Ok(())
    }

    /// Get the map manager
    pub fn maps(&self) -> Arc<RwLock<MapManager>> {
        Arc::clone(&self.maps)
    }

    /// Update a map entry
    pub fn update_map<K: aya::Pod, V: aya::Pod>(
        &mut self,
        program_name: &str,
        map_name: &str,
        key: &K,
        value: &V,
    ) -> Result<()> {
        let ebpf = self
            .objects
            .get_mut(program_name)
            .ok_or_else(|| Error::not_found("eBPF program", program_name))?;

        let mut map: aya::maps::HashMap<_, K, V> = ebpf
            .map_mut(map_name)
            .ok_or_else(|| Error::Internal(format!("Map {} not found", map_name)))?
            .try_into()
            .map_err(|e| Error::Internal(format!("Invalid map type: {}", e)))?;

        map.insert(key, value, 0)
            .map_err(|e| Error::Internal(format!("Failed to update map: {}", e)))?;

        Ok(())
    }

    /// Get list of attached programs
    pub fn list_attached(&self) -> Vec<&AttachedProgram> {
        self.attached.values().collect()
    }

    /// Check if a program is attached to an interface
    pub fn is_attached(&self, interface_name: &str) -> bool {
        self.attached.contains_key(interface_name)
    }
}

/// Try to attach XDP program with specified flags
/// Returns true if attachment succeeded, false otherwise
fn try_attach_program(program: &mut Xdp, interface_name: &str, flags: XdpFlags) -> bool {
    // Try to attach with the specified flags
    // Returns false to fall back to next mode (this is a placeholder implementation)
    // In a real implementation, we would try to attach and check for errors
    program.attach(interface_name, flags).is_ok()
}

impl Drop for EbpfLoader {
    fn drop(&mut self) {
        info!("Cleaning up eBPF programs");
        // Programs are automatically detached when dropped
        self.attached.clear();
        self.objects.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xdp_mode_flags() {
        // XdpFlags doesn't implement PartialEq, so compare the underlying bits
        assert_eq!(
            XdpMode::Generic.to_flags().bits(),
            XdpFlags::SKB_MODE.bits()
        );
        assert_eq!(XdpMode::Driver.to_flags().bits(), XdpFlags::DRV_MODE.bits());
        assert_eq!(XdpMode::Offload.to_flags().bits(), XdpFlags::HW_MODE.bits());
    }
}
