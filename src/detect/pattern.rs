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
/// IP addresses use ASCII digits, matching the `IpAddr` parser contract.
/// The first alternative handles plain IPv4 and `::ffff:`-mapped IPv4
/// (common in ProFTPD, Courier, PAM logs). The second handles pure IPv6.
const HOST_CAPTURE: &str =
    r"(?P<host>(?:::[fF]{4}:)?[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|[0-9a-fA-F:]{2,39})";

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

/// Extract a mandatory literal for Aho-Corasick pre-filtering.
///
/// Parses regex syntax and selects a mandatory exact literal. The literal may
/// occur on either side of HOST. Returns `None` when none is provably required.
pub fn literal_prefix(pattern: &str) -> Option<String> {
    let expanded = expand_host(pattern).ok()?;
    let hir = regex_syntax::parse(&expanded).ok()?;
    mandatory_literal(&hir).map(str::to_owned)
}

/// Only exact literals on a mandatory path may reject an entire regex.
/// HIR has already interpreted escapes, character classes and scoped flags.
fn mandatory_literal(hir: &regex_syntax::hir::Hir) -> Option<&str> {
    use regex_syntax::hir::HirKind;
    match hir.kind() {
        HirKind::Literal(lit) => std::str::from_utf8(&lit.0).ok().filter(|s| !s.is_empty()),
        HirKind::Capture(capture) if capture.name.as_deref() != Some("host") => {
            mandatory_literal(&capture.sub)
        }
        HirKind::Repetition(repetition) if repetition.min > 0 => mandatory_literal(&repetition.sub),
        HirKind::Concat(parts) => parts
            .iter()
            .filter_map(mandatory_literal)
            .max_by_key(|s| s.len()),
        // Alternatives and zero-minimum repetitions may omit any one literal.
        _ => None,
    }
}

/// Find an exact literal immediately preceding the host, with an unambiguous
/// token boundary after it. Otherwise named captures remain authoritative.
pub fn host_extractor(pattern: &str) -> HostExtractor {
    use regex_syntax::hir::{Hir, HirKind};
    fn flatten<'a>(hir: &'a Hir, parts: &mut Vec<&'a Hir>) {
        match hir.kind() {
            HirKind::Concat(children) => {
                for child in children {
                    flatten(child, parts);
                }
            }
            HirKind::Capture(c) if c.name.as_deref() != Some("host") => flatten(&c.sub, parts),
            _ => parts.push(hir),
        }
    }
    let Some(hir) = expand_host(pattern)
        .ok()
        .and_then(|p| regex_syntax::parse(&p).ok())
    else {
        return HostExtractor::Captures;
    };
    let mut parts = Vec::new();
    flatten(&hir, &mut parts);
    let Some(pos) = parts
        .iter()
        .position(|p| matches!(p.kind(), HirKind::Capture(c) if c.name.as_deref() == Some("host")))
    else {
        return HostExtractor::Captures;
    };
    // End-of-match or an exact non-IP separator prevents scanning into suffix
    // text. Regex assertions do not consume bytes and can be skipped here.
    let next = parts
        .iter()
        .skip(pos + 1)
        .find(|p| !matches!(p.kind(), HirKind::Look(_) | HirKind::Empty));
    let safe_end = match next.map(|p| p.kind()) {
        None => true,
        Some(HirKind::Literal(lit)) => lit
            .0
            .first()
            .is_some_and(|b| !b.is_ascii_hexdigit() && *b != b'.' && *b != b':'),
        _ => false,
    };
    if !safe_end {
        return HostExtractor::Captures;
    }
    if parts
        .iter()
        .take(pos)
        .all(|p| matches!(p.kind(), HirKind::Look(_) | HirKind::Empty))
    {
        return HostExtractor::AtStart;
    }
    if let Some(HirKind::Literal(lit)) = pos
        .checked_sub(1)
        .and_then(|i| parts.get(i))
        .map(|p| p.kind())
        && let Ok(literal) = std::str::from_utf8(&lit.0)
        && !literal.is_empty()
    {
        if literal.len() >= 2 {
            return HostExtractor::AfterLiteral(literal.to_owned());
        }
        // Mandatory non-IP separators on both sides delimit the full HOST
        // token, preserving sshd's common "... user .* HOST port" fast path.
        if literal
            .as_bytes()
            .last()
            .is_some_and(|b| !b.is_ascii_hexdigit() && *b != b'.' && *b != b':')
            && let Some(HirKind::Literal(suffix)) = next.map(|p| p.kind())
            && let Ok(suffix) = std::str::from_utf8(&suffix.0)
            && suffix.len() >= 2
        {
            return HostExtractor::BeforeLiteral(suffix.to_owned());
        }
        return HostExtractor::Captures;
    }
    HostExtractor::Captures
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
