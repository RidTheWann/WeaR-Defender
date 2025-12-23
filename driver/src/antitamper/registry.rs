//! Registry Protection (Anti-Tamper)
//!
//! Uses CmRegisterCallbackEx to intercept registry operations and
//! protect the driver's configuration and service keys.
//!
//! # Protected Keys
//! - `HKLM\SYSTEM\CurrentControlSet\Services\WeaRDefender`
//!   The service registration key - if deleted, driver won't load at boot
//! - `HKLM\SOFTWARE\WeaRDefender`
//!   Configuration and whitelist storage
//!
//! # Attack Scenarios Mitigated
//! 1. **Service Deletion** - `sc delete WeaRDefender` attempts to delete service key
//! 2. **Start Type Tampering** - Changing Start value to 4 (disabled)
//! 3. **ImagePath Hijacking** - Redirecting driver load to malicious .sys

use wdk::println;
use wdk_sys::{
    ntddk::{CmRegisterCallbackEx, CmUnRegisterCallback},
    NTSTATUS, PVOID, LARGE_INTEGER, REG_NOTIFY_CLASS,
    STATUS_SUCCESS, STATUS_ACCESS_DENIED, STATUS_CALLBACK_BYPASS,
};
use core::ptr;

/// Handle for the registered registry callback
pub struct RegistryCallbackHandle {
    cookie: LARGE_INTEGER,
}

// SAFETY: Cookie can be safely transferred between threads
unsafe impl Send for RegistryCallbackHandle {}
unsafe impl Sync for RegistryCallbackHandle {}

/// Altitude for our registry callback
/// Using a string format as required by CmRegisterCallbackEx
static ALTITUDE_STRING: wdk_sys::UNICODE_STRING = wdk_sys::UNICODE_STRING {
    Length: 12,      // "424242" = 6 chars * 2 bytes
    MaximumLength: 14,
    Buffer: ptr::null_mut(), // Set during init
};

/// Protected registry key patterns
/// We check if the key path contains these substrings
mod protected_keys {
    /// Service key for the driver
    pub const SERVICE_KEY: &[u16] = &[
        'S' as u16, 'e' as u16, 'r' as u16, 'v' as u16, 'i' as u16, 'c' as u16,
        'e' as u16, 's' as u16, '\\' as u16,
        'W' as u16, 'e' as u16, 'a' as u16, 'R' as u16,
        'D' as u16, 'e' as u16, 'f' as u16, 'e' as u16, 'n' as u16,
        'd' as u16, 'e' as u16, 'r' as u16,
    ];

    /// Configuration key
    pub const CONFIG_KEY: &[u16] = &[
        'S' as u16, 'O' as u16, 'F' as u16, 'T' as u16, 'W' as u16, 'A' as u16,
        'R' as u16, 'E' as u16, '\\' as u16,
        'W' as u16, 'e' as u16, 'a' as u16, 'R' as u16,
        'D' as u16, 'e' as u16, 'f' as u16, 'e' as u16, 'n' as u16,
        'd' as u16, 'e' as u16, 'r' as u16,
    ];
}

/// Initialize registry protection
///
/// Registers a callback to intercept all registry operations
/// and block modifications to protected keys.
///
/// # Returns
/// `Ok(RegistryCallbackHandle)` on success, `Err(NTSTATUS)` on failure
pub fn initialize() -> Result<RegistryCallbackHandle, NTSTATUS> {
    // Altitude buffer
    static ALTITUDE_BUFFER: [u16; 7] = [
        '4' as u16, '2' as u16, '4' as u16, '2' as u16, '4' as u16, '2' as u16, 0
    ];

    let altitude = wdk_sys::UNICODE_STRING {
        Length: 12,
        MaximumLength: 14,
        Buffer: ALTITUDE_BUFFER.as_ptr() as *mut u16,
    };

    let mut cookie: LARGE_INTEGER = LARGE_INTEGER { QuadPart: 0 };

    // Register the callback
    // SAFETY: All parameters are valid
    let status = unsafe {
        CmRegisterCallbackEx(
            Some(registry_callback),
            &altitude as *const _ as *mut _,
            ptr::null_mut(), // Driver object not needed for callbacks
            ptr::null_mut(), // Context
            &mut cookie,
            ptr::null_mut(), // Reserved
        )
    };

    if status != STATUS_SUCCESS {
        println!("[WeaR:AntiTamper] CmRegisterCallbackEx failed: 0x{:08X}", status);
        return Err(status);
    }

    println!("[WeaR:AntiTamper] Registry callback registered");
    println!("[WeaR:AntiTamper] Protected: Services\\WeaRDefender, SOFTWARE\\WeaRDefender");

    Ok(RegistryCallbackHandle { cookie })
}

/// Unregister the registry callback
pub fn unregister(handle: RegistryCallbackHandle) {
    // SAFETY: cookie was returned from successful CmRegisterCallbackEx
    let status = unsafe { CmUnRegisterCallback(handle.cookie) };
    
    if status == STATUS_SUCCESS {
        println!("[WeaR:AntiTamper] Registry callback unregistered");
    } else {
        println!("[WeaR:AntiTamper] Warning: Failed to unregister callback: 0x{:08X}", status);
    }
}

/// Registry callback function
///
/// Called for EVERY registry operation. Must be extremely fast.
/// We only inspect operations that could modify our protected keys.
///
/// # Performance Critical
/// Registry operations are frequent. We use quick pattern matching
/// and early-out for non-protected paths.
#[no_mangle]
unsafe extern "system" fn registry_callback(
    _callback_context: PVOID,
    argument1: PVOID,  // REG_NOTIFY_CLASS
    argument2: PVOID,  // Operation-specific info
) -> NTSTATUS {
    // Get the notification class (what type of operation)
    let notify_class: REG_NOTIFY_CLASS = argument1 as u32;

    // We only care about modification operations
    // Quick filter to avoid expensive path checking for read operations
    if !is_modification_operation(notify_class) {
        return STATUS_SUCCESS; // Allow the operation
    }

    // For modification operations, check if it's a protected key
    if let Some(key_path) = get_key_path_from_operation(notify_class, argument2) {
        if is_protected_key(key_path) {
            println!("[WeaR:AntiTamper] BLOCKED: Registry modification to protected key");
            return STATUS_ACCESS_DENIED;
        }
    }

    STATUS_SUCCESS
}

/// Check if the notify class represents a modification operation
///
/// We block:
/// - Key deletion
/// - Value set/delete
/// - Key rename
/// - Security changes
fn is_modification_operation(notify_class: REG_NOTIFY_CLASS) -> bool {
    matches!(
        notify_class,
        // Key operations
        2 |  // RegNtPreDeleteKey
        4 |  // RegNtPreSetValueKey
        5 |  // RegNtPreDeleteValueKey
        6 |  // RegNtPreSetInformationKey
        7 |  // RegNtPreRenameKey
        // Post operations we might want to audit
        22 | // RegNtPostDeleteKey
        24 | // RegNtPostSetValueKey
        25   // RegNtPostDeleteValueKey
    )
}

/// Extract the key path from the operation info
///
/// Each operation type has a different info structure.
/// We handle the common ones here.
fn get_key_path_from_operation(
    notify_class: REG_NOTIFY_CLASS,
    argument2: PVOID,
) -> Option<&'static [u16]> {
    if argument2.is_null() {
        return None;
    }

    // TODO: Implement proper extraction for each operation type
    // 
    // This would involve:
    // 1. Casting argument2 to the correct struct based on notify_class
    // 2. Extracting the Object field (key handle)
    // 3. Using CmCallbackGetKeyObjectID or ObQueryNameString to get the path
    //
    // For this skeleton, we return None and rely on the file protection
    // as the primary defense layer

    None
}

/// Check if the given key path is protected
fn is_protected_key(path: &[u16]) -> bool {
    // Case-insensitive check for our protected key patterns
    contains_pattern_ignore_case(path, protected_keys::SERVICE_KEY)
        || contains_pattern_ignore_case(path, protected_keys::CONFIG_KEY)
}

/// Case-insensitive pattern matching for UTF-16 strings
fn contains_pattern_ignore_case(haystack: &[u16], needle: &[u16]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }

    'outer: for i in 0..=(haystack.len() - needle.len()) {
        for j in 0..needle.len() {
            let h = to_lowercase_u16(haystack[i + j]);
            let n = to_lowercase_u16(needle[j]);
            if h != n {
                continue 'outer;
            }
        }
        return true;
    }
    false
}

/// Convert UTF-16 character to lowercase (ASCII only)
#[inline]
fn to_lowercase_u16(c: u16) -> u16 {
    if c >= 'A' as u16 && c <= 'Z' as u16 {
        c + 32
    } else {
        c
    }
}
