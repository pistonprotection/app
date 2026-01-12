//! PistonProtection Kubernetes Operator Library
//!
//! This library provides the core functionality for the PistonProtection operator.

pub mod client;
pub mod controllers;
pub mod crd;
pub mod error;
pub mod metrics;
pub mod worker;

#[cfg(test)]
mod tests;
