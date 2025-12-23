//! Filesystem Minifilter Module
//!
//! Implements file system filtering using FltRegisterFilter for:
//! - Self-protection (preventing modification of driver files)
//! - Sensitive directory protection
//! - Ransomware-like behavior detection

pub mod operations;

pub use operations::{initialize, unregister, FilterHandle};
