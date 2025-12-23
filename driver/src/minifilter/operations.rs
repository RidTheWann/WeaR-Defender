//! Minifilter Operations
//!
//! Implements file system filtering to protect sensitive files and detect
//! suspicious file access patterns.
//!
//! # Architecture
//! We register as a minifilter at a high altitude (424242) to intercept
//! file operations before other filters. This ensures our protection
//! cannot be bypassed by malicious filters.
//!
//! # Self-Protection
//! The primary goal is preventing ANY modification to our driver files,
//! even by Administrator or SYSTEM accounts.

use wdk::println;
use wdk_sys::{
    DRIVER_OBJECT, FLT_FILTER, FLT_REGISTRATION, FLT_OPERATION_REGISTRATION,
    FLT_PREOP_CALLBACK_STATUS, FLT_POSTOP_CALLBACK_STATUS,
    NTSTATUS, PCFLT_RELATED_OBJECTS, PFLT_CALLBACK_DATA, PFLT_FILTER,
    STATUS_SUCCESS, STATUS_ACCESS_DENIED, STATUS_FLT_DO_NOT_ATTACH,
    PVOID, ULONG,
    FLT_PREOP_SUCCESS_NO_CALLBACK, FLT_PREOP_COMPLETE,
    IRP_MJ_CREATE, IRP_MJ_WRITE, IRP_MJ_SET_INFORMATION,
    IRP_MJ_OPERATION_END,
};
use core::ptr;

/// Handle to the registered filter - needed for unregistration
pub struct FilterHandle {
    filter: PFLT_FILTER,
}

// SAFETY: Filter handle can be sent between threads (kernel synchronization handles this)
unsafe impl Send for FilterHandle {}
unsafe impl Sync for FilterHandle {}

/// Our minifilter altitude
/// 
/// RATIONALE: We use a high altitude (424242) to ensure we see operations
/// before most other filters. FSFilter Anti-Virus range is 320000-329999,
/// we're above that intentionally.
const FILTER_ALTITUDE: &[u8] = b"424242\0";

/// Filter registration structure
/// 
/// This is the main configuration for our minifilter, telling Windows
/// what operations we want to intercept and how.
static mut FILTER_REGISTRATION: FLT_REGISTRATION = FLT_REGISTRATION {
    Size: core::mem::size_of::<FLT_REGISTRATION>() as u16,
    Version: 0x0203, // FLT_REGISTRATION_VERSION for Win10+
    Flags: 0,
    ContextRegistration: ptr::null(),
    OperationRegistration: ptr::null(), // Set during init
    FilterUnloadCallback: Some(filter_unload_callback),
    InstanceSetupCallback: Some(instance_setup_callback),
    InstanceQueryTeardownCallback: None,
    InstanceTeardownStartCallback: None,
    InstanceTeardownCompleteCallback: None,
    GenerateFileNameCallback: None,
    NormalizeNameComponentCallback: None,
    NormalizeContextCleanupCallback: None,
    TransactionNotificationCallback: None,
    NormalizeNameComponentExCallback: None,
    SectionNotificationCallback: None,
};

/// Operations we want to filter
/// 
/// We intercept:
/// - IRP_MJ_CREATE: File open/create operations
/// - IRP_MJ_WRITE: Write operations (detect ransomware)
/// - IRP_MJ_SET_INFORMATION: Rename/delete operations
static OPERATION_CALLBACKS: [FLT_OPERATION_REGISTRATION; 4] = [
    // Filter file opens
    FLT_OPERATION_REGISTRATION {
        MajorFunction: IRP_MJ_CREATE,
        Flags: 0,
        PreOperation: Some(pre_create_callback),
        PostOperation: None,
        Reserved1: ptr::null_mut(),
    },
    // Filter writes
    FLT_OPERATION_REGISTRATION {
        MajorFunction: IRP_MJ_WRITE,
        Flags: 0,
        PreOperation: Some(pre_write_callback),
        PostOperation: None,
        Reserved1: ptr::null_mut(),
    },
    // Filter renames/deletes
    FLT_OPERATION_REGISTRATION {
        MajorFunction: IRP_MJ_SET_INFORMATION,
        Flags: 0,
        PreOperation: Some(pre_set_information_callback),
        PostOperation: None,
        Reserved1: ptr::null_mut(),
    },
    // End marker
    FLT_OPERATION_REGISTRATION {
        MajorFunction: IRP_MJ_OPERATION_END,
        Flags: 0,
        PreOperation: None,
        PostOperation: None,
        Reserved1: ptr::null_mut(),
    },
];

/// Initialize the minifilter
///
/// # Arguments
/// * `driver_object` - The driver object from DriverEntry
///
/// # Returns
/// `Ok(FilterHandle)` on success, `Err(NTSTATUS)` on failure
pub fn initialize(driver_object: *mut DRIVER_OBJECT) -> Result<FilterHandle, NTSTATUS> {
    // Set up operation registration
    // SAFETY: We're in initialization, no concurrent access yet
    unsafe {
        FILTER_REGISTRATION.OperationRegistration = OPERATION_CALLBACKS.as_ptr();
    }

    let mut filter_handle: PFLT_FILTER = ptr::null_mut();

    // Register the filter
    // SAFETY: driver_object is valid from DriverEntry, FILTER_REGISTRATION is static
    let status = unsafe {
        wdk_sys::fltKernel::FltRegisterFilter(
            driver_object as *mut _,
            &FILTER_REGISTRATION as *const _ as *mut _,
            &mut filter_handle,
        )
    };

    if status != STATUS_SUCCESS {
        println!("[WeaR:Minifilter] FltRegisterFilter failed: 0x{:08X}", status);
        return Err(status);
    }

    println!("[WeaR:Minifilter] Filter registered, starting...");

    // Start filtering
    // SAFETY: filter_handle is valid from successful FltRegisterFilter
    let status = unsafe {
        wdk_sys::fltKernel::FltStartFiltering(filter_handle)
    };

    if status != STATUS_SUCCESS {
        println!("[WeaR:Minifilter] FltStartFiltering failed: 0x{:08X}", status);
        // Clean up the registered filter
        unsafe {
            wdk_sys::fltKernel::FltUnregisterFilter(filter_handle);
        }
        return Err(status);
    }

    println!("[WeaR:Minifilter] Filtering started at altitude {}", 
        core::str::from_utf8(FILTER_ALTITUDE).unwrap_or("?"));

    Ok(FilterHandle { filter: filter_handle })
}

/// Unregister the minifilter
pub fn unregister(handle: FilterHandle) {
    if !handle.filter.is_null() {
        // SAFETY: handle.filter was returned from successful FltRegisterFilter
        unsafe {
            wdk_sys::fltKernel::FltUnregisterFilter(handle.filter);
        }
        println!("[WeaR:Minifilter] Filter unregistered");
    }
}

/// Filter unload callback
/// 
/// Called when the filter is being unloaded. We return success to allow
/// unloading (required for development). In production, you might want
/// to return STATUS_FLT_DO_NOT_DETACH to prevent unloading.
#[no_mangle]
unsafe extern "system" fn filter_unload_callback(
    _flags: ULONG,
) -> NTSTATUS {
    println!("[WeaR:Minifilter] Unload callback invoked");
    STATUS_SUCCESS
}

/// Instance setup callback
///
/// Called when the filter attaches to a volume. We attach to all local
/// fixed drives but skip network and removable drives for performance.
#[no_mangle]
unsafe extern "system" fn instance_setup_callback(
    _flt_objects: PCFLT_RELATED_OBJECTS,
    _flags: ULONG,
    _volume_device_type: ULONG,
    _volume_filesystem_type: ULONG,
) -> NTSTATUS {
    // TODO: In production, check volume type and skip:
    // - Network drives (performance)
    // - Removable drives (optional)
    // - Read-only volumes (no protection needed)
    
    println!("[WeaR:Minifilter] Attaching to volume");
    STATUS_SUCCESS
}

/// Pre-create callback
///
/// Intercepts file open/create operations. This is where we implement
/// self-protection by blocking access to our own files.
///
/// # Self-Protection Logic
/// - Block ALL write/delete access to driver files
/// - Allow read access (needed for signature verification)
/// - Log blocked attempts for auditing
#[no_mangle]
unsafe extern "system" fn pre_create_callback(
    data: PFLT_CALLBACK_DATA,
    _flt_objects: PCFLT_RELATED_OBJECTS,
    _completion_context: *mut PVOID,
) -> FLT_PREOP_CALLBACK_STATUS {
    if data.is_null() {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // SAFETY: data is not null (checked above) and we're in callback context
    let callback_data = unsafe { &*data };
    
    // Get the file name from the operation
    // For performance, we only check if this looks like our protected path
    if is_protected_file_operation(callback_data) {
        // Check if this is a write/delete operation
        if is_write_or_delete_access(callback_data) {
            println!("[WeaR:Minifilter] BLOCKED: Attempt to modify protected file");
            
            // Block the operation
            // SAFETY: We're modifying our own callback data
            unsafe {
                (*data).IoStatus.Anonymous.Status = STATUS_ACCESS_DENIED;
            }
            return FLT_PREOP_COMPLETE;
        }
    }

    FLT_PREOP_SUCCESS_NO_CALLBACK
}

/// Pre-write callback
///
/// Intercepts write operations. We use this to:
/// 1. Protect our own files from modification
/// 2. Detect ransomware-like behavior (rapid encrypted writes)
#[no_mangle]
unsafe extern "system" fn pre_write_callback(
    data: PFLT_CALLBACK_DATA,
    flt_objects: PCFLT_RELATED_OBJECTS,
    _completion_context: *mut PVOID,
) -> FLT_PREOP_CALLBACK_STATUS {
    if data.is_null() {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Check if this is a write to a protected file
    let callback_data = unsafe { &*data };
    
    if is_protected_file_operation(callback_data) {
        println!("[WeaR:Minifilter] BLOCKED: Write to protected file");
        unsafe {
            (*data).IoStatus.Anonymous.Status = STATUS_ACCESS_DENIED;
        }
        return FLT_PREOP_COMPLETE;
    }

    // TODO: Implement ransomware detection
    // - Track write patterns per process
    // - Detect high-entropy data (encrypted content)
    // - Monitor for extension changes (.encrypted, .locked, etc.)

    FLT_PREOP_SUCCESS_NO_CALLBACK
}

/// Pre-set-information callback
///
/// Intercepts rename and delete operations. Critical for:
/// 1. Preventing deletion of our driver files
/// 2. Detecting ransomware file rename patterns
#[no_mangle]
unsafe extern "system" fn pre_set_information_callback(
    data: PFLT_CALLBACK_DATA,
    _flt_objects: PCFLT_RELATED_OBJECTS,
    _completion_context: *mut PVOID,
) -> FLT_PREOP_CALLBACK_STATUS {
    if data.is_null() {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    let callback_data = unsafe { &*data };
    
    // Block any modification info operation on protected files
    // This includes rename, delete, and attribute changes
    if is_protected_file_operation(callback_data) {
        println!("[WeaR:Minifilter] BLOCKED: Set info on protected file");
        unsafe {
            (*data).IoStatus.Anonymous.Status = STATUS_ACCESS_DENIED;
        }
        return FLT_PREOP_COMPLETE;
    }

    FLT_PREOP_SUCCESS_NO_CALLBACK
}

/// Check if the operation targets a protected file
///
/// # Protected Files
/// - wear_defender.sys (our driver)
/// - Files in our configuration directory
fn is_protected_file_operation(_data: &wdk_sys::FLT_CALLBACK_DATA) -> bool {
    // TODO: Implement actual path checking
    // 
    // In production, this would:
    // 1. Call FltGetFileNameInformation to get the file path
    // 2. Compare against protected path list
    // 3. Cache results for performance
    //
    // For this skeleton, we return false to avoid blocking everything
    false
}

/// Check if the access mask includes write or delete
fn is_write_or_delete_access(_data: &wdk_sys::FLT_CALLBACK_DATA) -> bool {
    // TODO: Check IoParameterBlock for access mask
    // 
    // The access mask would include:
    // - FILE_WRITE_DATA
    // - FILE_APPEND_DATA
    // - DELETE
    // - FILE_WRITE_ATTRIBUTES
    
    false
}
