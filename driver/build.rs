//! Build script for WeaR Defender kernel driver
//!
//! This script configures the WDK build environment and generates
//! necessary bindings for Windows kernel APIs.

fn main() -> Result<(), wdk_build::ConfigError> {
    // Configure WDK library linkage
    // This sets up the correct library paths and generates FFI bindings
    wdk_build::configure_wdk_library_build()?;

    // Re-run if WDK version changes
    println!("cargo:rerun-if-env-changed=WDK_VERSION");
    println!("cargo:rerun-if-env-changed=WDK_INFVERIF_PATH");

    // Link against required kernel libraries
    println!("cargo:rustc-link-lib=ntoskrnl");   // NT Kernel
    println!("cargo:rustc-link-lib=hal");        // Hardware Abstraction Layer
    println!("cargo:rustc-link-lib=wmilib");     // WMI support
    println!("cargo:rustc-link-lib=fltMgr");     // Filter Manager for minifilter

    Ok(())
}
