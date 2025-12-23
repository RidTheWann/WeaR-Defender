//! Memory Integrity Guard Implementation
//!
//! Uses ObRegisterCallbacks to intercept handle operations and strip
//! dangerous access rights that could be used for code injection.
//!
//! # Attack Vectors Mitigated
//! 
//! 1. **DLL Injection via CreateRemoteThread**
//!    - Requires PROCESS_CREATE_THREAD + PROCESS_VM_WRITE + PROCESS_VM_OPERATION
//!    - We strip these when cross-process
//!
//! 2. **Process Hollowing**
//!    - Requires PROCESS_VM_WRITE to overwrite image
//!    - We detect and block memory writes to executable sections
//!
//! 3. **Handle Duplication Attacks**
//!    - Attacker duplicates handle with elevated access
//!    - We intercept and deny access escalation
//!
//! # HVCI Compliance
//! This module doesn't generate code - it only filters handle access rights.

use wdk::println;
use wdk_sys::{
    ntddk::{ObRegisterCallbacks, ObUnRegisterCallbacks},
    DRIVER_OBJECT, NTSTATUS, PVOID, OB_CALLBACK_REGISTRATION, OB_OPERATION_REGISTRATION,
    OB_PREOP_CALLBACK_STATUS, POB_PRE_OPERATION_INFORMATION,
    STATUS_SUCCESS, STATUS_UNSUCCESSFUL, ACCESS_MASK,
    PsProcessType, PsThreadType,
};
use core::ptr;

/// Handle to the registered object callbacks
pub struct ObjectCallbackHandle {
    registration_handle: PVOID,
}

// SAFETY: Handle can be transferred between threads
unsafe impl Send for ObjectCallbackHandle {}
unsafe impl Sync for ObjectCallbackHandle {}

/// Dangerous access rights that enable code injection
/// We strip these when a process tries to get a handle to another process
const DANGEROUS_PROCESS_ACCESS: ACCESS_MASK = 
    0x0002 |    // PROCESS_CREATE_THREAD
    0x0008 |    // PROCESS_VM_OPERATION  
    0x0010 |    // PROCESS_VM_READ (optional, for stealth)
    0x0020;     // PROCESS_VM_WRITE

/// Dangerous thread access rights
const DANGEROUS_THREAD_ACCESS: ACCESS_MASK =
    0x0002 |    // THREAD_SUSPEND_RESUME
    0x0010 |    // THREAD_GET_CONTEXT
    0x0008;     // THREAD_SET_CONTEXT

/// Operations registration for process handles
static mut PROCESS_OPERATION: OB_OPERATION_REGISTRATION = OB_OPERATION_REGISTRATION {
    ObjectType: ptr::null_mut(), // Set to PsProcessType during init
    Operations: 0x03, // OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE
    PreOperation: Some(process_handle_pre_callback),
    PostOperation: None,
};

/// Operations registration for thread handles
static mut THREAD_OPERATION: OB_OPERATION_REGISTRATION = OB_OPERATION_REGISTRATION {
    ObjectType: ptr::null_mut(), // Set to PsThreadType during init
    Operations: 0x03, // OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE
    PreOperation: Some(thread_handle_pre_callback),
    PostOperation: None,
};

/// Altitude for object callbacks
/// Using same altitude as our minifilter for consistency
static ALTITUDE: wdk_sys::UNICODE_STRING = wdk_sys::UNICODE_STRING {
    Length: 12,      // "424242" = 6 chars * 2 bytes
    MaximumLength: 14,
    Buffer: ptr::null_mut(), // Set during initialization
};

/// Initialize the memory integrity guard
///
/// Registers callbacks for process and thread handle operations.
///
/// # Arguments
/// * `driver_object` - Driver object from DriverEntry
///
/// # Returns
/// `Ok(ObjectCallbackHandle)` on success, `Err(NTSTATUS)` on failure
pub fn initialize(driver_object: *mut DRIVER_OBJECT) -> Result<ObjectCallbackHandle, NTSTATUS> {
    // Get the actual object type pointers
    // SAFETY: These are kernel exports, always valid
    let process_type = unsafe { *PsProcessType };
    let thread_type = unsafe { *PsThreadType };

    if process_type.is_null() || thread_type.is_null() {
        println!("[WeaR:Memory] Failed to get process/thread object types");
        return Err(STATUS_UNSUCCESSFUL);
    }

    // Set up the operation registrations
    // SAFETY: We're in initialization, single-threaded
    unsafe {
        PROCESS_OPERATION.ObjectType = PsProcessType;
        THREAD_OPERATION.ObjectType = PsThreadType;
    }

    // Build the operations array
    let operations: [OB_OPERATION_REGISTRATION; 2] = unsafe {
        [PROCESS_OPERATION, THREAD_OPERATION]
    };

    // Altitude string buffer (static lifetime)
    static ALTITUDE_BUFFER: [u16; 7] = [
        '4' as u16, '2' as u16, '4' as u16, '2' as u16, '4' as u16, '2' as u16, 0
    ];

    // Build the callback registration
    let altitude = wdk_sys::UNICODE_STRING {
        Length: 12,
        MaximumLength: 14,
        Buffer: ALTITUDE_BUFFER.as_ptr() as *mut u16,
    };

    let callback_registration = OB_CALLBACK_REGISTRATION {
        Version: 0x0100, // OB_FLT_REGISTRATION_VERSION
        OperationRegistrationCount: 2,
        Altitude: altitude,
        RegistrationContext: ptr::null_mut(),
        OperationRegistration: operations.as_ptr() as *mut _,
    };

    let mut registration_handle: PVOID = ptr::null_mut();

    // Register the callbacks
    // SAFETY: callback_registration is valid, driver_object is from DriverEntry
    let status = unsafe {
        ObRegisterCallbacks(
            &callback_registration as *const _ as *mut _,
            &mut registration_handle,
        )
    };

    if status != STATUS_SUCCESS {
        println!("[WeaR:Memory] ObRegisterCallbacks failed: 0x{:08X}", status);
        return Err(status);
    }

    println!("[WeaR:Memory] Object callbacks registered for process and thread handles");

    Ok(ObjectCallbackHandle { registration_handle })
}

/// Unregister object callbacks
pub fn unregister(handle: ObjectCallbackHandle) {
    if !handle.registration_handle.is_null() {
        // SAFETY: Handle was returned from successful ObRegisterCallbacks
        unsafe {
            ObUnRegisterCallbacks(handle.registration_handle);
        }
        println!("[WeaR:Memory] Object callbacks unregistered");
    }
}

/// Pre-operation callback for process handle operations
///
/// This is called BEFORE a handle to a process is created or duplicated.
/// We examine the requested access rights and strip dangerous ones.
///
/// # Strategy: Access Right Stripping
/// Rather than denying the entire operation (which could break apps),
/// we strip the dangerous access rights. The caller gets a handle,
/// but it can't be used for injection.
#[no_mangle]
unsafe extern "system" fn process_handle_pre_callback(
    _registration_context: PVOID,
    operation_info: POB_PRE_OPERATION_INFORMATION,
) -> OB_PREOP_CALLBACK_STATUS {
    if operation_info.is_null() {
        return 0; // OB_PREOP_SUCCESS
    }

    // SAFETY: operation_info is valid (checked above)
    let info = unsafe { &mut *operation_info };

    // Don't filter kernel-mode callers - they're trusted
    if info.KernelHandle != 0 {
        return 0; // OB_PREOP_SUCCESS
    }

    // Get the accessing and target processes
    let accessor = get_current_process();
    let target = info.Object as *mut _;

    // Allow processes to open handles to themselves
    if accessor == target {
        return 0; // OB_PREOP_SUCCESS
    }

    // This is a CROSS-PROCESS handle operation
    // Strip dangerous access rights
    
    // For handle creation
    if info.Operation == 1 { // OB_OPERATION_HANDLE_CREATE
        let create_info = unsafe { &mut *info.Parameters.CreateHandleInformation };
        let original_access = create_info.DesiredAccess;
        
        // Strip dangerous rights
        create_info.DesiredAccess &= !DANGEROUS_PROCESS_ACCESS;
        
        if create_info.DesiredAccess != original_access {
            println!(
                "[WeaR:Memory] Stripped process access: 0x{:08X} -> 0x{:08X}",
                original_access, create_info.DesiredAccess
            );
        }
    }
    
    // For handle duplication
    if info.Operation == 2 { // OB_OPERATION_HANDLE_DUPLICATE
        let dup_info = unsafe { &mut *info.Parameters.DuplicateHandleInformation };
        let original_access = dup_info.DesiredAccess;
        
        dup_info.DesiredAccess &= !DANGEROUS_PROCESS_ACCESS;
        
        if dup_info.DesiredAccess != original_access {
            println!(
                "[WeaR:Memory] Stripped duplicated process access: 0x{:08X} -> 0x{:08X}",
                original_access, dup_info.DesiredAccess
            );
        }
    }

    0 // OB_PREOP_SUCCESS
}

/// Pre-operation callback for thread handle operations
///
/// Similar to process handles, but for threads. Prevents:
/// - Thread context manipulation (get/set context)
/// - Thread suspension (used in some injection techniques)
#[no_mangle]
unsafe extern "system" fn thread_handle_pre_callback(
    _registration_context: PVOID,
    operation_info: POB_PRE_OPERATION_INFORMATION,
) -> OB_PREOP_CALLBACK_STATUS {
    if operation_info.is_null() {
        return 0; // OB_PREOP_SUCCESS
    }

    let info = unsafe { &mut *operation_info };

    // Don't filter kernel-mode callers
    if info.KernelHandle != 0 {
        return 0; // OB_PREOP_SUCCESS
    }

    // Get owning process of the target thread
    // If it's the same as the caller's process, allow full access
    // TODO: Implement thread-to-process owner check

    // For now, strip dangerous thread rights for all cross-process access
    if info.Operation == 1 { // OB_OPERATION_HANDLE_CREATE
        let create_info = unsafe { &mut *info.Parameters.CreateHandleInformation };
        let original = create_info.DesiredAccess;
        
        create_info.DesiredAccess &= !DANGEROUS_THREAD_ACCESS;
        
        if create_info.DesiredAccess != original {
            println!(
                "[WeaR:Memory] Stripped thread access: 0x{:08X} -> 0x{:08X}",
                original, create_info.DesiredAccess
            );
        }
    }

    if info.Operation == 2 { // OB_OPERATION_HANDLE_DUPLICATE
        let dup_info = unsafe { &mut *info.Parameters.DuplicateHandleInformation };
        let original = dup_info.DesiredAccess;
        
        dup_info.DesiredAccess &= !DANGEROUS_THREAD_ACCESS;
        
        if dup_info.DesiredAccess != original {
            println!(
                "[WeaR:Memory] Stripped duplicated thread access: 0x{:08X} -> 0x{:08X}",
                original, dup_info.DesiredAccess
            );
        }
    }

    0 // OB_PREOP_SUCCESS
}

/// Get the current process (caller context)
fn get_current_process() -> PVOID {
    // SAFETY: PsGetCurrentProcess is always safe to call
    unsafe { wdk_sys::ntddk::PsGetCurrentProcess() as PVOID }
}
