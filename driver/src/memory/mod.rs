//! Memory Integrity Guard Module
//!
//! Implements handle and memory protection using ObRegisterCallbacks to:
//! - Prevent code injection (DLL injection, Process Hollowing)
//! - Protect driver process handles from being opened with dangerous access
//! - Detect and block cross-process memory manipulation

pub mod guard;

pub use guard::{initialize, unregister, ObjectCallbackHandle};
