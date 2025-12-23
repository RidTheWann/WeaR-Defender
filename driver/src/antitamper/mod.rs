//! Anti-Tamper Module
//!
//! Protects the driver's own registry keys and configuration from
//! modification, even by Administrator or SYSTEM accounts.

pub mod registry;

pub use registry::{initialize, unregister, RegistryCallbackHandle};
