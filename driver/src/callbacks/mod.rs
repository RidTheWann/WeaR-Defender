//! Process Creation Callbacks Module
//!
//! Implements the "Deny-by-Default" process creation policy using
//! PsSetCreateProcessNotifyRoutineEx.

pub mod process;

pub use process::{register_process_notify, unregister_process_notify};
