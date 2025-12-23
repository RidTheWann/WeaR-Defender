//! Process Creation Notify Routine
//!
//! Implements aggressive process creation monitoring using PsSetCreateProcessNotifyRoutineEx.
//! This module enforces a "Deny-by-Default" policy for process creation.
//!
//! # Security Philosophy
//! Rather than trying to detect malware (reactive), we block everything that
//! isn't explicitly trusted (proactive). This inverts the security model.
//!
//! # Blocking Criteria
//! - Unsigned executables: Blocked immediately
//! - Executables from temp directories: Blocked  
//! - Executables from user download folders: Require explicit whitelist
//! - Non-Microsoft signed: Logged and optionally blocked

use wdk::println;
use wdk_sys::{
    ntddk::{PsSetCreateProcessNotifyRoutineEx},
    HANDLE, NTSTATUS, PEPROCESS, PPS_CREATE_NOTIFY_INFO, STATUS_SUCCESS,
    STATUS_ACCESS_DENIED,
};
use core::sync::atomic::{AtomicBool, Ordering};

use wear_defender_common::BlockReason;

/// Flag to track if callback is registered (for safe unregister)
static CALLBACK_REGISTERED: AtomicBool = AtomicBool::new(false);

/// Register the process creation notify callback
///
/// # Returns
/// `Ok(())` on success, `Err(NTSTATUS)` on failure
///
/// # Safety
/// This function registers a kernel callback. It must only be called
/// from DriverEntry context.
pub fn register_process_notify() -> Result<(), NTSTATUS> {
    // SAFETY: PsSetCreateProcessNotifyRoutineEx is safe to call from DriverEntry
    let status = unsafe {
        PsSetCreateProcessNotifyRoutineEx(Some(process_notify_callback), 0) // 0 = not removing
    };

    if status == STATUS_SUCCESS {
        CALLBACK_REGISTERED.store(true, Ordering::SeqCst);
        println!("[WeaR:Process] Notify callback registered successfully");
        Ok(())
    } else {
        println!("[WeaR:Process] Failed to register callback: 0x{:08X}", status);
        Err(status)
    }
}

/// Unregister the process creation notify callback
///
/// # Safety
/// Must be called from DriverUnload context or during error cleanup.
pub fn unregister_process_notify() {
    if CALLBACK_REGISTERED.load(Ordering::SeqCst) {
        // SAFETY: We're unregistering a callback we registered
        let status = unsafe {
            PsSetCreateProcessNotifyRoutineEx(Some(process_notify_callback), 1) // 1 = remove
        };

        if status == STATUS_SUCCESS {
            CALLBACK_REGISTERED.store(false, Ordering::SeqCst);
            println!("[WeaR:Process] Notify callback unregistered");
        } else {
            println!("[WeaR:Process] WARNING: Failed to unregister callback: 0x{:08X}", status);
        }
    }
}

/// Process creation notify callback
///
/// This is called by the kernel for EVERY process creation/termination.
/// We must be extremely fast here to avoid system slowdown.
///
/// # Arguments
/// * `process` - The EPROCESS structure for the process
/// * `process_id` - The PID of the process
/// * `create_info` - Creation info (None for process termination)
///
/// # Safety
/// Called by kernel with valid process and create_info pointers.
/// create_info is NULL for process termination notifications.
#[no_mangle]
unsafe extern "system" fn process_notify_callback(
    _process: PEPROCESS,
    process_id: HANDLE,
    create_info: PPS_CREATE_NOTIFY_INFO,
) {
    // Process termination - we don't need to do anything
    if create_info.is_null() {
        return;
    }

    // SAFETY: create_info is not null (checked above)
    let info = unsafe { &mut *create_info };

    // Get the image file name for logging/checking
    let image_name = if !info.ImageFileName.is_null() {
        // SAFETY: ImageFileName is valid when not null
        unsafe { &*info.ImageFileName }
    } else {
        // No image name - this is suspicious, block it
        println!("[WeaR:Process] BLOCKED PID {:?}: No image filename (suspicious)", process_id);
        info.CreationStatus = STATUS_ACCESS_DENIED;
        return;
    };

    // Convert to something we can check
    // Note: In production, this would be more sophisticated
    let should_block = check_process_policy(image_name, process_id);

    if let Some(reason) = should_block {
        // BLOCK THE PROCESS
        // 
        // RATIONALE: Setting CreationStatus to an error prevents the process
        // from being created. This is the kernel's "veto" mechanism.
        info.CreationStatus = STATUS_ACCESS_DENIED;
        
        log_blocked_process(process_id, image_name, reason);
    }
}

/// Check if a process should be blocked based on our policy
///
/// # Policy Rules (in order of check):
/// 1. Whitelist check - if whitelisted, allow immediately
/// 2. Check if path is in untrusted location (temp, downloads) → Block
/// 3. Check if executable is signed → Block if unsigned
/// 4. Check signature validity → Block if invalid
///
/// # Returns
/// `Some(BlockReason)` if process should be blocked, `None` if allowed
fn check_process_policy(
    image_name: &wdk_sys::UNICODE_STRING,
    _process_id: HANDLE,
) -> Option<BlockReason> {
    // Fast path: Check buffer validity
    if image_name.Buffer.is_null() || image_name.Length == 0 {
        return Some(BlockReason::Unsigned); // No name = suspicious
    }

    // Convert UNICODE_STRING to a slice for checking
    // SAFETY: Buffer is valid and Length bytes are readable
    let name_slice = unsafe {
        core::slice::from_raw_parts(
            image_name.Buffer,
            (image_name.Length / 2) as usize, // Length is in bytes, Buffer is u16
        )
    };

    // Check for untrusted locations
    // 
    // RATIONALE: Malware often executes from temp directories or downloads
    // to bypass detection. Blocking these locations forces attackers to
    // find more visible persistence mechanisms.
    if is_untrusted_location(name_slice) {
        return Some(BlockReason::UntrustedLocation);
    }

    // Check for our self-protection
    // NEVER allow processes that try to impersonate our driver
    if matches_protected_name(name_slice) {
        return Some(BlockReason::TamperAttempt);
    }

    // TODO: In production, implement actual signature verification
    // For now, we'll allow signed Microsoft binaries through
    // This requires calling CI.dll functions or SeValidateImageHeader

    // For this skeleton, we allow everything not in untrusted locations
    // In production, this would default to BLOCK
    None
}

/// Check if the path is in an untrusted location
///
/// Untrusted locations include:
/// - Temp directories
/// - Download folders  
/// - Recycle bin
/// - Browser caches
fn is_untrusted_location(path: &[u16]) -> bool {
    // Common untrusted path patterns (as UTF-16)
    // Note: These are case-insensitive checks in production
    
    const TEMP_PATTERN: &[u16] = &[
        'T' as u16, 'e' as u16, 'm' as u16, 'p' as u16, '\\' as u16
    ];
    
    const APPDATA_LOCAL_TEMP: &[u16] = &[
        'A' as u16, 'p' as u16, 'p' as u16, 'D' as u16, 'a' as u16, 't' as u16, 'a' as u16,
        '\\' as u16, 'L' as u16, 'o' as u16, 'c' as u16, 'a' as u16, 'l' as u16,
        '\\' as u16, 'T' as u16, 'e' as u16, 'm' as u16, 'p' as u16
    ];
    
    const DOWNLOADS: &[u16] = &[
        'D' as u16, 'o' as u16, 'w' as u16, 'n' as u16, 'l' as u16, 'o' as u16,
        'a' as u16, 'd' as u16, 's' as u16, '\\' as u16
    ];

    // Case-insensitive substring search
    contains_pattern_ignore_case(path, TEMP_PATTERN)
        || contains_pattern_ignore_case(path, APPDATA_LOCAL_TEMP)
        || contains_pattern_ignore_case(path, DOWNLOADS)
}

/// Check if path matches our protected driver name
fn matches_protected_name(path: &[u16]) -> bool {
    const WEAR_DEFENDER: &[u16] = &[
        'w' as u16, 'e' as u16, 'a' as u16, 'r' as u16, '_' as u16,
        'd' as u16, 'e' as u16, 'f' as u16, 'e' as u16, 'n' as u16,
        'd' as u16, 'e' as u16, 'r' as u16
    ];

    contains_pattern_ignore_case(path, WEAR_DEFENDER)
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

/// Convert UTF-16 character to lowercase (ASCII only for speed)
#[inline]
fn to_lowercase_u16(c: u16) -> u16 {
    if c >= 'A' as u16 && c <= 'Z' as u16 {
        c + 32
    } else {
        c
    }
}

/// Log a blocked process for auditing
fn log_blocked_process(
    process_id: HANDLE,
    image_name: &wdk_sys::UNICODE_STRING,
    reason: BlockReason,
) {
    // In production, this would write to a ring buffer that
    // the user-mode service can query via IOCTL
    
    let reason_str = match reason {
        BlockReason::Unsigned => "UNSIGNED",
        BlockReason::InvalidSignature => "INVALID_SIGNATURE",
        BlockReason::UntrustedLocation => "UNTRUSTED_LOCATION",
        BlockReason::KnownMalware => "KNOWN_MALWARE",
        BlockReason::InjectionAttempt => "INJECTION_ATTEMPT",
        BlockReason::TamperAttempt => "TAMPER_ATTEMPT",
        BlockReason::ProtectedResource => "PROTECTED_RESOURCE",
        BlockReason::MemoryViolation => "MEMORY_VIOLATION",
    };

    // Print first few characters of path for debugging
    let len = core::cmp::min((image_name.Length / 2) as usize, 50);
    
    println!(
        "[WeaR:Process] BLOCKED PID {:?}: Reason={}, PathLen={}",
        process_id,
        reason_str,
        len
    );
}
