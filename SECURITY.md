# Security Policy

## Scope

WeaR Defender is a kernel-mode Windows security project. Vulnerabilities in kernel code can cause system instability, privilege escalation, data corruption, or system compromise.

## Supported Development Target

Security reports should identify the affected component and, when possible:

- Windows 11 x64
- WDK and Windows SDK versions used for the test
- Rust toolchain version
- Build configuration (Debug or Release)
- Reproduction steps or a minimal proof of concept

## Reporting a Vulnerability

Please do not publish exploitable vulnerability details in a public issue.

Use the repository's private security reporting mechanism when available. Until a private channel is configured, report only non-sensitive documentation issues publicly and avoid posting working exploits, secrets, crash dumps containing sensitive data, or personal information.

A useful report should include:

1. A concise description of the vulnerability.
2. The affected component, file, or callback.
3. Reproduction steps and expected versus actual behavior.
4. Impact assessment, including whether the issue can cross a security boundary.
5. Any mitigation or patch you have already tested.

## Safety

Do not test kernel-driver changes on production systems. Prefer an isolated virtual machine or dedicated test machine with recovery media and current backups.

## Disclosure

Please allow reasonable time for investigation, remediation, and release of a fix before public disclosure of a security vulnerability.
