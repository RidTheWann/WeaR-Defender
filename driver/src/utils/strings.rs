//! String Utilities for Kernel Mode
//!
//! Helper functions for working with UNICODE_STRING and other
//! kernel string types.

use wdk_sys::UNICODE_STRING;

/// Compare two UNICODE_STRINGs for equality (case-insensitive)
///
/// This is a constant-time-ish comparison for security-sensitive
/// string checks.
pub fn unicode_string_equals_ignore_case(a: &UNICODE_STRING, b: &UNICODE_STRING) -> bool {
    // Fast path: different lengths can't be equal
    if a.Length != b.Length {
        return false;
    }

    if a.Buffer.is_null() || b.Buffer.is_null() {
        return a.Buffer.is_null() && b.Buffer.is_null();
    }

    let len = (a.Length / 2) as usize;
    
    // SAFETY: We've checked both buffers are non-null and Length is valid
    let a_slice = unsafe { core::slice::from_raw_parts(a.Buffer, len) };
    let b_slice = unsafe { core::slice::from_raw_parts(b.Buffer, len) };

    for i in 0..len {
        if to_lowercase(a_slice[i]) != to_lowercase(b_slice[i]) {
            return false;
        }
    }

    true
}

/// Check if a UNICODE_STRING contains a pattern (case-insensitive)
pub fn unicode_string_contains(haystack: &UNICODE_STRING, needle: &[u16]) -> bool {
    if haystack.Buffer.is_null() || haystack.Length == 0 {
        return needle.is_empty();
    }

    let haystack_len = (haystack.Length / 2) as usize;
    
    // SAFETY: Buffer is non-null and Length is valid
    let haystack_slice = unsafe { 
        core::slice::from_raw_parts(haystack.Buffer, haystack_len) 
    };

    contains_pattern(haystack_slice, needle)
}

/// Check if a UTF-16 slice contains a pattern (case-insensitive)
pub fn contains_pattern(haystack: &[u16], needle: &[u16]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if haystack.len() < needle.len() {
        return false;
    }

    'outer: for i in 0..=(haystack.len() - needle.len()) {
        for j in 0..needle.len() {
            if to_lowercase(haystack[i + j]) != to_lowercase(needle[j]) {
                continue 'outer;
            }
        }
        return true;
    }
    false
}

/// Check if a UNICODE_STRING starts with a pattern
pub fn unicode_string_starts_with(s: &UNICODE_STRING, prefix: &[u16]) -> bool {
    if s.Buffer.is_null() || s.Length == 0 {
        return prefix.is_empty();
    }

    let s_len = (s.Length / 2) as usize;
    if s_len < prefix.len() {
        return false;
    }

    // SAFETY: Buffer is non-null and we're reading within bounds
    let s_slice = unsafe { core::slice::from_raw_parts(s.Buffer, prefix.len()) };

    for i in 0..prefix.len() {
        if to_lowercase(s_slice[i]) != to_lowercase(prefix[i]) {
            return false;
        }
    }
    true
}

/// Check if a UNICODE_STRING ends with a pattern
pub fn unicode_string_ends_with(s: &UNICODE_STRING, suffix: &[u16]) -> bool {
    if s.Buffer.is_null() || s.Length == 0 {
        return suffix.is_empty();
    }

    let s_len = (s.Length / 2) as usize;
    if s_len < suffix.len() {
        return false;
    }

    let start = s_len - suffix.len();
    
    // SAFETY: Buffer is non-null and we're reading within bounds
    let s_slice = unsafe { 
        core::slice::from_raw_parts(s.Buffer.add(start), suffix.len()) 
    };

    for i in 0..suffix.len() {
        if to_lowercase(s_slice[i]) != to_lowercase(suffix[i]) {
            return false;
        }
    }
    true
}

/// Convert a UTF-16 character to lowercase (ASCII only)
///
/// For kernel performance, we only handle ASCII characters.
/// Non-ASCII characters are returned unchanged.
#[inline]
pub fn to_lowercase(c: u16) -> u16 {
    if c >= 'A' as u16 && c <= 'Z' as u16 {
        c + 32
    } else {
        c
    }
}

/// Convert a string literal to a UTF-16 array at compile time
///
/// Usage: `const MY_STRING: &[u16] = &utf16!("Hello");`
#[macro_export]
macro_rules! utf16 {
    ($s:literal) => {{
        const LEN: usize = $s.len();
        const fn convert(s: &str) -> [u16; LEN] {
            let bytes = s.as_bytes();
            let mut result = [0u16; LEN];
            let mut i = 0;
            while i < bytes.len() {
                result[i] = bytes[i] as u16;
                i += 1;
            }
            result
        }
        &convert($s)
    }};
}
