//! eBPF program definitions
//!
//! This module contains the embedded eBPF programs that will be loaded
//! at runtime. The actual eBPF bytecode is compiled separately and
//! included at build time.

/// XDP program for DDoS filtering
pub const XDP_FILTER_PROGRAM: &[u8] = include_bytes!("../../ebpf-programs/xdp_filter.o");

/// XDP program for rate limiting
pub const XDP_RATELIMIT_PROGRAM: &[u8] = include_bytes!("../../ebpf-programs/xdp_ratelimit.o");

/// XDP program for connection tracking
pub const XDP_CONNTRACK_PROGRAM: &[u8] = include_bytes!("../../ebpf-programs/xdp_conntrack.o");

/// XDP program for Minecraft protocol filtering
pub const XDP_MINECRAFT_PROGRAM: &[u8] = include_bytes!("../../ebpf-programs/xdp_minecraft.o");

/// XDP program for HTTP/QUIC filtering
pub const XDP_HTTP_PROGRAM: &[u8] = include_bytes!("../../ebpf-programs/xdp_http.o");

// Note: The above includes will fail until we create the actual eBPF programs.
// For now, we'll use a placeholder approach.

/// Placeholder for eBPF programs (until real programs are compiled)
pub mod placeholder {
    /// Get placeholder program bytes
    /// In production, these would be actual compiled eBPF bytecode
    pub fn get_filter_program() -> Vec<u8> {
        // This would be replaced with actual eBPF bytecode
        Vec::new()
    }

    pub fn get_ratelimit_program() -> Vec<u8> {
        Vec::new()
    }

    pub fn get_conntrack_program() -> Vec<u8> {
        Vec::new()
    }

    pub fn get_minecraft_program() -> Vec<u8> {
        Vec::new()
    }

    pub fn get_http_program() -> Vec<u8> {
        Vec::new()
    }
}

/// Program configuration
#[derive(Debug, Clone)]
pub struct ProgramConfig {
    /// Program name
    pub name: String,
    /// Program type
    pub program_type: ProgramType,
    /// Map configurations
    pub maps: Vec<MapConfig>,
}

/// Program type
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ProgramType {
    XdpFilter,
    XdpRateLimit,
    XdpConnTrack,
    XdpMinecraft,
    XdpHttp,
}

/// Map configuration
#[derive(Debug, Clone)]
pub struct MapConfig {
    pub name: String,
    pub map_type: MapType,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
}

/// eBPF map types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MapType {
    Hash,
    Array,
    PerCpuHash,
    PerCpuArray,
    LruHash,
    LpmTrie,
    RingBuf,
}

/// Get the default filter program configuration
pub fn default_filter_config() -> ProgramConfig {
    ProgramConfig {
        name: "xdp_filter".to_string(),
        program_type: ProgramType::XdpFilter,
        maps: vec![
            MapConfig {
                name: "blocked_ips".to_string(),
                map_type: MapType::LruHash,
                key_size: 16, // IPv6 address size
                value_size: 32, // BlockedIpEntry
                max_entries: 1_000_000,
            },
            MapConfig {
                name: "rate_limits".to_string(),
                map_type: MapType::PerCpuHash,
                key_size: 16,
                value_size: 24,
                max_entries: 100_000,
            },
            MapConfig {
                name: "config".to_string(),
                map_type: MapType::Array,
                key_size: 4,
                value_size: 64,
                max_entries: 1,
            },
            MapConfig {
                name: "stats".to_string(),
                map_type: MapType::PerCpuArray,
                key_size: 4,
                value_size: 64,
                max_entries: 16, // Different stat counters
            },
        ],
    }
}

/// Get the Minecraft protocol filter configuration
pub fn minecraft_filter_config() -> ProgramConfig {
    ProgramConfig {
        name: "xdp_minecraft".to_string(),
        program_type: ProgramType::XdpMinecraft,
        maps: vec![
            MapConfig {
                name: "mc_connections".to_string(),
                map_type: MapType::LruHash,
                key_size: 20, // IP + port
                value_size: 48, // Connection state
                max_entries: 500_000,
            },
            MapConfig {
                name: "mc_handshakes".to_string(),
                map_type: MapType::PerCpuHash,
                key_size: 16,
                value_size: 32,
                max_entries: 100_000,
            },
            MapConfig {
                name: "mc_config".to_string(),
                map_type: MapType::Array,
                key_size: 4,
                value_size: 128,
                max_entries: 1,
            },
        ],
    }
}

/// Get the HTTP/QUIC filter configuration
pub fn http_filter_config() -> ProgramConfig {
    ProgramConfig {
        name: "xdp_http".to_string(),
        program_type: ProgramType::XdpHttp,
        maps: vec![
            MapConfig {
                name: "http_connections".to_string(),
                map_type: MapType::LruHash,
                key_size: 20,
                value_size: 64,
                max_entries: 1_000_000,
            },
            MapConfig {
                name: "quic_connections".to_string(),
                map_type: MapType::LruHash,
                key_size: 36, // Connection ID up to 20 bytes + metadata
                value_size: 48,
                max_entries: 500_000,
            },
            MapConfig {
                name: "http_config".to_string(),
                map_type: MapType::Array,
                key_size: 4,
                value_size: 256,
                max_entries: 1,
            },
        ],
    }
}
