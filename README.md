# WeaR Defender

A next-generation Endpoint Protection Platform (EPP) implemented as a Windows Kernel-Mode Driver using Rust. Designed with a "Zero Trust" philosophy at Ring 0, providing stricter security enforcement than traditional antivirus solutions.

## Overview

WeaR Defender is a kernel-level security driver that intercepts and controls:

- **Process Creation** - Deny-by-default policy for unsigned or untrusted binaries
- **File System Operations** - Self-protection and sensitive directory monitoring
- **Memory Access** - Prevention of code injection techniques (DLL injection, Process Hollowing)
- **Registry Modifications** - Protection of driver configuration and service keys

## Architecture

```
+------------------+     +------------------+
|   User Mode      |     |   Kernel Mode    |
|   Service        |<--->|   WeaR Driver    |
+------------------+     +------------------+
        |                        |
        v                        v
+------------------+     +------------------+
|   Configuration  |     |   Callbacks      |
|   & Whitelist    |     |   - Process      |
+------------------+     |   - Minifilter   |
                         |   - Memory       |
                         |   - Registry     |
                         +------------------+
```

## Features

### Process Monitor (PsSetCreateProcessNotifyRoutineEx)
- Intercepts all process creation events
- Blocks executables from untrusted locations (Temp, Downloads)
- Self-protection against driver impersonation
- Comprehensive logging of blocked processes

### Filesystem Minifilter (FltRegisterFilter)
- Registered at altitude 424242 (above standard AV filters)
- Intercepts IRP_MJ_CREATE, IRP_MJ_WRITE, IRP_MJ_SET_INFORMATION
- Protects driver files from modification or deletion
- Ransomware behavior detection framework

### Memory Integrity Guard (ObRegisterCallbacks)
- Strips dangerous access rights from cross-process handles
- Prevents PROCESS_CREATE_THREAD + PROCESS_VM_WRITE combinations
- Blocks THREAD_SET_CONTEXT for thread hijacking prevention
- Allows legitimate same-process operations

### Anti-Tamper (CmRegisterCallbackEx)
- Protects HKLM\SYSTEM\CurrentControlSet\Services\WeaRDefender
- Protects HKLM\SOFTWARE\WeaRDefender configuration
- Blocks all modifications including from SYSTEM account

## Requirements

### Development Environment
- Windows 11 SDK (10.0.22621.0 or later)
- Windows Driver Kit (WDK)
- Rust nightly toolchain
- cargo-wdk extension

### System Requirements
- Windows 11 (x64)
- Test signing enabled for development
- EV Code Signing certificate for production deployment
- WHQL certification for public distribution

## Building

### Install Prerequisites

```powershell
# Install Rust nightly
rustup install nightly
rustup default nightly
rustup component add rust-src llvm-tools-preview

# Install cargo-wdk
cargo install cargo-wdk
```

### Build the Driver

```powershell
cd WeaR-Defender

# Using cargo-wdk
cargo wdk build --release

# Or standard cargo build
cargo build --release
```

### Verify INF File

```powershell
infverif /v driver\wear_defender.inf
```

## Installation

> WARNING: Kernel drivers can cause system instability. Always test in a virtual machine first.

### Development Testing

```powershell
# Enable test signing (requires reboot)
bcdedit /set testsigning on

# Install the driver
sc create WeaRDefender type=kernel binpath="C:\path\to\wear_defender.sys"

# Start the driver
sc start WeaRDefender

# Verify status
sc query WeaRDefender
```

### Uninstallation

```powershell
sc stop WeaRDefender
sc delete WeaRDefender
```

## Project Structure

```
WeaR-Defender/
├── Cargo.toml                    # Workspace manifest
├── rust-toolchain.toml           # Nightly toolchain config
├── LICENSE                       # MIT License
├── README.md                     # This file
│
├── .cargo/
│   └── config.toml               # Kernel linker configuration
│
├── driver/
│   ├── Cargo.toml                # Driver crate manifest
│   ├── build.rs                  # WDK build script
│   ├── wear_defender.inx         # INF template
│   └── src/
│       ├── lib.rs                # DriverEntry and initialization
│       ├── callbacks/
│       │   ├── mod.rs
│       │   └── process.rs        # Process creation monitoring
│       ├── minifilter/
│       │   ├── mod.rs
│       │   └── operations.rs     # File system filtering
│       ├── memory/
│       │   ├── mod.rs
│       │   └── guard.rs          # Handle access protection
│       ├── antitamper/
│       │   ├── mod.rs
│       │   └── registry.rs       # Registry protection
│       └── utils/
│           ├── mod.rs
│           └── strings.rs        # UNICODE_STRING helpers
│
└── common/
    ├── Cargo.toml                # Shared types crate
    └── src/
        └── lib.rs                # IOCTL codes and constants
```

## HVCI Compliance

This driver is designed to be compatible with Hypervisor-Protected Code Integrity:

| Requirement | Status |
|-------------|--------|
| No dynamic code generation | Compliant |
| Control Flow Guard enabled | Compliant |
| Integrity check flag | Compliant |
| EV Code Signing | Required for production |

## Security Considerations

- This is a proof-of-concept implementation
- Production deployment requires thorough security auditing
- Driver bugs can cause Blue Screen of Death (BSOD)
- Never test on production systems without proper backups
- Requires EV code signing and WHQL certification for distribution

## Contributing

1. Fork the repository
2. Create a feature branch
3. Test thoroughly in a virtual machine
4. Submit a pull request with detailed description

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

**RidTheWann**

## Acknowledgments

- Microsoft for the windows-drivers-rs project
- The Rust community for no_std ecosystem development
- Windows Driver Kit documentation and samples
