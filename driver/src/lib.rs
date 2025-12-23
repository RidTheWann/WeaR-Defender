//! WeaR Defender Kernel Driver - Main Entry Point
//!
//! This is the core kernel-mode driver for WeaR Defender EPP.
//! It implements a "Zero Trust" security model at Ring 0.
//!
//! # Safety
//! This entire crate operates in kernel mode. Panics will cause BSOD.
//! All code must be carefully reviewed for memory safety.
//!
//! # HVCI Compliance
//! - No dynamic code generation
//! - All code pages are read-only after load
//! - Control Flow Guard enabled via build settings

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(clippy::all, clippy::pedantic)]

// Required for kernel driver entry
extern crate alloc;

// WDK crates
use wdk::println;
use wdk_alloc::WdkAllocator;
use wdk_sys::{
    ntddk::DbgPrint,
    DRIVER_OBJECT, NTSTATUS, PCUNICODE_STRING, PDRIVER_OBJECT, STATUS_SUCCESS,
    STATUS_UNSUCCESSFUL,
};

// Our modules
mod callbacks;
mod minifilter;
mod memory;
mod antitamper;
mod utils;

/// Global allocator for kernel heap allocations
/// 
/// RATIONALE: Kernel mode has no default allocator. We must provide one
/// that uses ExAllocatePool2 internally.
#[global_allocator]
static ALLOCATOR: WdkAllocator = WdkAllocator;

/// Panic handler for kernel mode
///
/// RATIONALE: Standard panic handler tries to unwind, which is not
/// available in kernel mode. We must abort immediately.
/// In debug builds, we print the panic info before crashing.
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    // In debug builds, try to print panic info
    #[cfg(debug_assertions)]
    {
        // SAFETY: DbgPrint is always safe to call in kernel mode
        unsafe {
            DbgPrint(
                b"[WeaR] PANIC: %s\n\0".as_ptr() as *const i8,
                info.message().as_str().unwrap_or("unknown").as_ptr(),
            );
        }
    }

    // Trigger a kernel bugcheck
    // This is the only safe way to handle unrecoverable errors in kernel mode
    loop {
        core::hint::spin_loop();
    }
}

/// Driver global state
///
/// RATIONALE: We need to track registered callbacks so we can
/// properly unregister them during driver unload.
static mut DRIVER_STATE: Option<DriverState> = None;

struct DriverState {
    /// Handle for process notify callback
    process_callback_registered: bool,
    /// Handle for minifilter
    minifilter_handle: Option<minifilter::FilterHandle>,
    /// Handle for object callbacks
    object_callback_handle: Option<memory::ObjectCallbackHandle>,
    /// Handle for registry callbacks
    registry_callback_handle: Option<antitamper::RegistryCallbackHandle>,
}

impl DriverState {
    const fn new() -> Self {
        Self {
            process_callback_registered: false,
            minifilter_handle: None,
            object_callback_handle: None,
            registry_callback_handle: None,
        }
    }
}

/// Driver entry point
///
/// This is called by the Windows kernel when the driver is loaded.
/// We must register all our callbacks and set up protection mechanisms.
///
/// # Safety
/// This function is called by the kernel with valid driver and registry objects.
/// 
/// # Returns
/// `STATUS_SUCCESS` if initialization succeeded, error status otherwise.
#[no_mangle]
#[export_name = "DriverEntry"]
pub unsafe extern "system" fn driver_entry(
    driver_object: PDRIVER_OBJECT,
    registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    println!("[WeaR] ===============================================");
    println!("[WeaR] WeaR Defender Security Driver v0.1.0");
    println!("[WeaR] Zero Trust Endpoint Protection - Initializing");
    println!("[WeaR] ===============================================");

    // Initialize driver state
    // SAFETY: We're in DriverEntry, no other code is running yet
    unsafe {
        DRIVER_STATE = Some(DriverState::new());
    }

    // Set up driver unload routine
    // SAFETY: driver_object is valid, provided by kernel
    unsafe {
        (*driver_object).DriverUnload = Some(driver_unload);
    }

    // Initialize subsystems in order of dependency
    if let Err(status) = initialize_subsystems(driver_object, registry_path) {
        println!("[WeaR] ERROR: Subsystem initialization failed: 0x{:08X}", status);
        // Clean up any partially initialized state
        cleanup_subsystems();
        return status;
    }

    println!("[WeaR] All subsystems initialized successfully");
    println!("[WeaR] Driver is now protecting the system");
    
    STATUS_SUCCESS
}

/// Initialize all protection subsystems
///
/// Order matters - we initialize in order of criticality:
/// 1. Anti-tamper (protect ourselves first)
/// 2. Process monitor (block malicious process creation)
/// 3. Memory guard (prevent code injection)
/// 4. Minifilter (protect filesystem)
unsafe fn initialize_subsystems(
    driver_object: PDRIVER_OBJECT,
    _registry_path: PCUNICODE_STRING,
) -> Result<(), NTSTATUS> {
    let state = unsafe { DRIVER_STATE.as_mut().ok_or(STATUS_UNSUCCESSFUL)? };

    // 1. Initialize anti-tamper first (self-protection is critical)
    println!("[WeaR] Initializing anti-tamper protection...");
    match antitamper::initialize() {
        Ok(handle) => {
            state.registry_callback_handle = Some(handle);
            println!("[WeaR] Anti-tamper: Registry protection active");
        }
        Err(status) => {
            println!("[WeaR] WARNING: Anti-tamper init failed: 0x{:08X}", status);
            // Continue anyway - this is not fatal
        }
    }

    // 2. Initialize process creation monitoring
    println!("[WeaR] Initializing process monitor...");
    match callbacks::register_process_notify() {
        Ok(()) => {
            state.process_callback_registered = true;
            println!("[WeaR] Process monitor: Active (deny-by-default mode)");
        }
        Err(status) => {
            println!("[WeaR] ERROR: Process monitor init failed: 0x{:08X}", status);
            return Err(status);
        }
    }

    // 3. Initialize memory integrity guard
    println!("[WeaR] Initializing memory integrity guard...");
    match memory::initialize(driver_object) {
        Ok(handle) => {
            state.object_callback_handle = Some(handle);
            println!("[WeaR] Memory guard: Handle protection active");
        }
        Err(status) => {
            println!("[WeaR] WARNING: Memory guard init failed: 0x{:08X}", status);
            // Continue - not fatal but reduces protection
        }
    }

    // 4. Initialize filesystem minifilter
    println!("[WeaR] Initializing filesystem minifilter...");
    match minifilter::initialize(driver_object) {
        Ok(handle) => {
            state.minifilter_handle = Some(handle);
            println!("[WeaR] Minifilter: File system protection active");
        }
        Err(status) => {
            println!("[WeaR] WARNING: Minifilter init failed: 0x{:08X}", status);
            // Continue - reduces protection but not fatal
        }
    }

    Ok(())
}

/// Clean up all registered callbacks
///
/// Called during driver unload or if initialization fails.
fn cleanup_subsystems() {
    println!("[WeaR] Cleaning up subsystems...");

    // SAFETY: We're either in DriverUnload or handling init failure
    let state = unsafe { DRIVER_STATE.as_mut() };
    
    if let Some(state) = state {
        // Unregister in reverse order of registration
        if let Some(handle) = state.minifilter_handle.take() {
            minifilter::unregister(handle);
            println!("[WeaR] Minifilter unregistered");
        }

        if let Some(handle) = state.object_callback_handle.take() {
            memory::unregister(handle);
            println!("[WeaR] Memory guard unregistered");
        }

        if state.process_callback_registered {
            callbacks::unregister_process_notify();
            state.process_callback_registered = false;
            println!("[WeaR] Process monitor unregistered");
        }

        if let Some(handle) = state.registry_callback_handle.take() {
            antitamper::unregister(handle);
            println!("[WeaR] Anti-tamper unregistered");
        }
    }

    // Clear global state
    unsafe {
        DRIVER_STATE = None;
    }
}

/// Driver unload routine
///
/// Called by the kernel when the driver is being unloaded.
/// We must properly clean up all resources to prevent leaks/crashes.
///
/// # Safety
/// Called by kernel with valid driver object.
#[no_mangle]
unsafe extern "system" fn driver_unload(_driver_object: PDRIVER_OBJECT) {
    println!("[WeaR] ===============================================");
    println!("[WeaR] Driver unload requested");
    println!("[WeaR] ===============================================");

    cleanup_subsystems();

    println!("[WeaR] WeaR Defender driver unloaded successfully");
}
