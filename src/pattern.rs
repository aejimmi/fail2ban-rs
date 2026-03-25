//! Pattern expansion and literal prefix extraction.
//!
//! User-facing patterns use `<HOST>` as a placeholder for the IP capture group.
//! This module expands `<HOST>` into a regex that matches both IPv4 and IPv6
//! addresses, and extracts literal prefixes for Aho-Corasick pre-filtering.

use crate::error::{Error, Result};

/// Non-capturing host group: matches IPv4 or IPv6 addresses.
const HOST_CAPTURE: &str = r"(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[0-9a-fA-F:]{2,39})";

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
