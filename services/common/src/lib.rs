//! PistonProtection Common Library
//!
//! Shared utilities, configuration, and abstractions used across all services.

pub mod config;
pub mod db;
pub mod error;
pub mod geoip;
pub mod metrics;
pub mod ratelimit;
pub mod redis;
pub mod telemetry;

pub use config::Config;
pub use error::{Error, Result};

/// Service metadata
pub struct ServiceInfo {
    pub name: &'static str,
    pub version: &'static str,
}

impl ServiceInfo {
    pub const fn new(name: &'static str) -> Self {
        Self {
            name,
            version: env!("CARGO_PKG_VERSION"),
        }
    }
}
