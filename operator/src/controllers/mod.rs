//! Controller implementations for PistonProtection CRDs
//!
//! This module contains the reconciliation logic for all custom resources:
//! - DDoSProtection: Main protection configuration
//! - FilterRule: Custom filtering rules
//! - Backend: Backend service definitions
//! - IPBlocklist: IP blocklist management

pub mod backend;
pub mod ddos_protection;
pub mod filter_rule;
pub mod ip_blocklist;

// Re-export for convenience
pub use backend::Context as BackendContext;
pub use ddos_protection::Context as DDoSProtectionContext;
pub use filter_rule::Context as FilterRuleContext;
pub use ip_blocklist::Context as IPBlocklistContext;
