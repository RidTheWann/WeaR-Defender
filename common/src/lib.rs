//! WeaR Defender Common Library
//!
//! Shared types, constants, and IOCTL codes used by both
//! the kernel driver and user-mode service.
//!
//! This crate is `no_std` compatible for kernel use.

#![no_std]
#![cfg_attr(feature = "std", no_std = false)]

/// Driver identification constants
pub mod driver {
    /// Driver service name (must match INF)
    pub const SERVICE_NAME: &str = "WeaRDefender";
    
    /// Driver display name
    pub const DISPLAY_NAME: &str = "WeaR Defender Security Driver";
    
    /// Driver file name
    pub const FILE_NAME: &str = "wear_defender.sys";
    
    /// Driver symbolic link for user-mode communication
    pub const SYMBOLIC_LINK: &str = "\\??\\WeaRDefender";
    
    /// Device name in kernel namespace
    pub const DEVICE_NAME: &str = "\\Device\\WeaRDefender";
}

/// IOCTL codes for driver communication
///
/// Using METHOD_BUFFERED for safety - kernel copies data to system buffer
pub mod ioctl {
    /// Base code for WeaR Defender IOCTLs
    /// Using 0x8000+ range (vendor-defined)
    const DEVICE_TYPE: u32 = 0x8000;
    
    /// CTL_CODE macro equivalent
    const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
        (device_type << 16) | (access << 14) | (function << 2) | method
    }
    
    // Method types
    const METHOD_BUFFERED: u32 = 0;
    
    // Access types
    const FILE_READ_ACCESS: u32 = 1;
    const FILE_WRITE_ACCESS: u32 = 2;
    const FILE_ANY_ACCESS: u32 = 0;
    
    /// Get driver version and status
    pub const GET_STATUS: u32 = ctl_code(DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS);
    
    /// Add process to whitelist (requires admin)
    pub const ADD_WHITELIST: u32 = ctl_code(DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_WRITE_ACCESS);
    
    /// Remove process from whitelist
    pub const REMOVE_WHITELIST: u32 = ctl_code(DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_WRITE_ACCESS);
    
    /// Query blocked process log
    pub const GET_BLOCKED_LOG: u32 = ctl_code(DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_READ_ACCESS);
    
    /// Emergency disable (requires special token)
    pub const EMERGENCY_DISABLE: u32 = ctl_code(DEVICE_TYPE, 0x8FF, METHOD_BUFFERED, FILE_ANY_ACCESS);
}

/// Process blocking reasons
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockReason {
    /// Binary is not signed
    Unsigned = 1,
    /// Binary is signed but signature is invalid
    InvalidSignature = 2,
    /// Binary is from untrusted location (temp, downloads)
    UntrustedLocation = 3,
    /// Binary hash matches known malware
    KnownMalware = 4,
    /// Binary attempting code injection
    InjectionAttempt = 5,
    /// Process attempting to tamper with driver
    TamperAttempt = 6,
    /// Access to protected file/directory
    ProtectedResource = 7,
    /// Memory integrity violation
    MemoryViolation = 8,
}

/// Driver status structure returned via IOCTL
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DriverStatus {
    /// Driver version (major.minor.patch as u32)
    pub version: u32,
    /// Number of processes blocked since boot
    pub blocked_count: u64,
    /// Number of file operations blocked
    pub file_blocks: u64,
    /// Number of injection attempts blocked
    pub injection_blocks: u64,
    /// Driver is in enforcement mode (true) or audit mode (false)  
    pub enforcement_mode: bool,
    /// Reserved for future use
    pub _reserved: [u8; 7],
}

/// Protected paths that should be blocked from modification
pub mod protected_paths {
    /// System directories that require extra protection
    pub const SYSTEM_DIRS: &[&str] = &[
        "\\Windows\\System32\\drivers\\",
        "\\Windows\\System32\\config\\",
        "\\Windows\\SysWOW64\\drivers\\",
    ];
    
    /// WeaR Defender's own files (absolute protection)
    pub const SELF_PROTECTION: &[&str] = &[
        "\\Windows\\System32\\drivers\\wear_defender.sys",
        "\\ProgramData\\WeaRDefender\\",
    ];
}
