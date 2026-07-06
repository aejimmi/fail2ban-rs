//! Pattern expansion and literal prefix extraction.
//!
//! User-facing patterns use `<HOST>` as a placeholder for the IP capture group.
//! This module expands `<HOST>` into a regex that matches both IPv4 and IPv6
//! addresses, and extracts literal prefixes for Aho-Corasick pre-filtering.

use crate::error::{Error, Result};

/// Named capture group for the host IP (IPv4, IPv4-mapped IPv6, or IPv6).
///
/// Using a named group lets `try_match()` extract the IP from the exact
/// `<HOST>` position via `captures()`, instead of scanning the full match
/// span — which breaks when other IPs appear in the matched text.
///
/// The first alternative handles plain IPv4 and `::ffff:`-mapped IPv4
/// (common in ProFTPD, Courier, PAM logs). The second handles pure IPv6.
const HOST_CAPTURE: &str =
    r"(?P<host>(?:::[fF]{4}:)?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[0-9a-fA-F:]{2,39})";

/// The placeholder token in user patterns.
const HOST_TAG: &str = "<HOST>";

/// Expand `<HOST>` in a user pattern into the IP capture group regex.
///
/// Returns an error if the pattern contains zero or more than one `<HOST>`.
pub fn expand_host(pattern: &str) -> Result<String> {
    let count = pattern.matches(HOST_TAG).count();
    if count == 0 {
        return Err(Error::config(format!(
            "pattern missing <HOST> placeholder: {pattern}"
        )));
    }
    if count > 1 {
        return Err(Error::config(format!(
            "pattern has multiple <HOST> placeholders ({count}): {pattern}"
        )));
    }
    Ok(pattern.replace(HOST_TAG, HOST_CAPTURE))
}

/// Strategy for extracting the host IP from a regex match span.
///
/// Determined at compile time from the pattern structure around `<HOST>`.
#[derive(Debug, Clone)]
pub enum HostExtractor {
    /// `<HOST>` is at the start of the pattern (or after `^`).
    /// Extract IP from the beginning of the match span.
    AtStart,
    /// `<HOST>` is preceded by this literal string.
    /// Search for the literal in the match span, extract IP after it.
    AfterLiteral(String),
    /// `<HOST>` is followed by this literal string.
    /// Search for the literal in the match span, extract the rightmost IP
    /// token immediately before it.
    BeforeLiteral(String),
    /// Ambiguous context — fall back to `captures()`.
    Captures,
}

/// Regex metacharacters used to identify literal boundaries.
const META_CHARS: &[char] = &[
    '\\', '.', '*', '+', '?', '(', ')', '[', ']', '{', '}', '|', '^', '$',
];

/// Determine how to extract the host IP for a given pattern.
///
/// Examines the literal text around `<HOST>` to decide the fastest
/// extraction strategy. Falls back to `Captures` only when neither
/// the before nor after literal is usable.
pub fn host_extractor(pattern: &str) -> HostExtractor {
    let Some(host_pos) = pattern.find(HOST_TAG) else {
        return HostExtractor::Captures;
    };
    let before = &pattern[..host_pos];
    let after = &pattern[host_pos + HOST_TAG.len()..];

    // HOST at the very start, or only preceded by ^ anchor.
    if before.is_empty() || before.chars().all(|c| c == '^') {
        return HostExtractor::AtStart;
    }

    // Try literal immediately before HOST.
    let lit_before = trailing_literal(before);
    if lit_before.len() >= 2 {
        let prefix_before_literal = &before[..before.len() - lit_before.len()];
        if !prefix_before_literal.contains(&*lit_before) {
            return HostExtractor::AfterLiteral(lit_before);
        }
    }

    // Try literal immediately after HOST.
    let lit_after = leading_literal(after);
    if lit_after.len() >= 2 && !before.contains(&*lit_after) {
        return HostExtractor::BeforeLiteral(lit_after);
    }

    HostExtractor::Captures
}

/// Extract contiguous literal characters from the end of `s`.
fn trailing_literal(s: &str) -> String {
    let start = s
        .rfind(|c: char| META_CHARS.contains(&c))
        .map_or(0, |pos| pos + 1);
    s[start..].to_string()
}

/// Extract contiguous literal characters from the start of `s`.
fn leading_literal(s: &str) -> String {
    let end = s.find(|c: char| META_CHARS.contains(&c)).unwrap_or(s.len());
    s[..end].to_string()
}

/// Extract the literal prefix before `<HOST>` for Aho-Corasick pre-filtering.
///
/// Walks backwards from the `<HOST>` position to find the longest substring
/// that contains no regex metacharacters. Returns `None` if no usable literal
/// prefix exists (e.g. pattern starts with `<HOST>`).
pub fn literal_prefix(pattern: &str) -> Option<String> {
    let host_pos = pattern.find(HOST_TAG)?;
    let before = &pattern[..host_pos];
    if before.is_empty() {
        return None;
    }

    // Walk backwards from the end of `before` to find a literal run.
    // Stop at regex metacharacters.
    let meta_chars = &[
        '\\', '.', '*', '+', '?', '(', ')', '[', ']', '{', '}', '|', '^', '$',
    ];
    let literal_start = before
        .rfind(|c: char| meta_chars.contains(&c))
        .map_or(0, |pos| pos + 1);

    let trailing = &before[literal_start..];

    // If the trailing segment is long enough, use it directly.
    if trailing.len() >= 3 {
        return Some(trailing.to_string());
    }

    // Trailing segment is too short (e.g. " " from `user .* <HOST>`).
    // Search the whole prefix for a longer literal segment.
    if let Some(longer) = extract_longest_literal(before) {
        return Some(longer);
    }

    // Fall back to short trailing segment (still better than nothing).
    if !trailing.is_empty() {
        return Some(trailing.to_string());
    }

    None
}

/// Find the longest contiguous literal (no metacharacters) segment in `s`.
fn extract_longest_literal(s: &str) -> Option<String> {
    let meta_chars = &[
        '\\', '.', '*', '+', '?', '(', ')', '[', ']', '{', '}', '|', '^', '$',
    ];
    let mut best = "";
    let mut current_start = 0;

    for (i, c) in s.char_indices() {
        if meta_chars.contains(&c) {
            let segment = &s[current_start..i];
            if segment.len() > best.len() {
                best = segment;
            }
            current_start = i + c.len_utf8();
        }
    }
    // Check the last segment
    let segment = &s[current_start..];
    if segment.len() > best.len() {
        best = segment;
    }

    if best.len() >= 3 {
        Some(best.to_string())
    } else {
        None
    }
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::needless_pass_by_value
)]
#[path = "pattern_test.rs"]
mod pattern_test;
