//! Byte-to-text decoding shared by log readers and firewall listing parsers.

use std::borrow::Cow;

/// Decode bytes as UTF-8, replacing invalid sequences.
///
/// Valid input is validated with SIMD and borrowed without allocation;
/// invalid input falls back to std lossy decoding.
#[must_use]
pub fn lossy(bytes: &[u8]) -> Cow<'_, str> {
    if let Ok(text) = simdutf8::basic::from_utf8(bytes) {
        Cow::Borrowed(text)
    } else {
        String::from_utf8_lossy(bytes)
    }
}
