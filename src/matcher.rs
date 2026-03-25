//! Fast matching engine for log lines.
//!
//! Phase 1: Aho-Corasick automaton over deduplicated literal prefixes rejects
//! non-matching lines in ~10ns.
//! Phase 2: AC-guided regex selection — only tries regexes whose literal
//! prefix was found in the line, skipping impossible patterns.
//! IP extraction uses `find()` (DFA only) instead of `captures()` (PikeVM),
//! then scans the match span for the IP token.

use std::net::IpAddr;

use aho_corasick::AhoCorasick;
use regex::Regex;

use crate::error::{Error, Result};
use crate::pattern;

/// Result of a successful match against a log line.
#[derive(Debug, Clone)]
pub struct MatchResult {
    /// The extracted IP address.
    pub ip: IpAddr,
    /// Index of the pattern that matched.
    pub pattern_idx: usize,
}

/// Per-jail matching engine.
pub struct JailMatcher {
    /// Aho-Corasick automaton for literal prefix filtering.
    /// `None` if no patterns have usable literal prefixes.
    ac: Option<AhoCorasick>,
    /// Individual compiled regexes (with `<HOST>` expanded).
    regexes: Vec<Regex>,
    /// Compiled ignoreregex patterns — matched lines are suppressed.
    ignore_regexes: Vec<Regex>,
    /// Maps each AC pattern slot → regex indices to try. Deduplicated:
    /// patterns sharing the same literal prefix are grouped under one slot.
    ac_to_regex: Vec<Vec<usize>>,
}

impl JailMatcher {
    /// Build a matcher from user-facing patterns (containing `<HOST>`).
    pub fn new(patterns: &[String]) -> Result<Self> {
        if patterns.is_empty() {
            return Err(Error::config("no patterns provided"));
        }

        // Expand <HOST> in all patterns.
        let expanded: Vec<String> = patterns
            .iter()
            .map(|p| pattern::expand_host(p))
            .collect::<Result<Vec<_>>>()?;

        // Build individual regexes.
        let regexes: Vec<Regex> = expanded
            .iter()
            .zip(patterns.iter())
            .map(|(p, orig)| {
                Regex::new(p).map_err(|e| Error::Regex {
                    pattern: orig.clone(),
                    source: e,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        // Extract and deduplicate literal prefixes for Aho-Corasick.
        // Patterns sharing the same prefix are grouped under one AC slot.
        let mut unique_prefixes: Vec<String> = Vec::new();
        let mut ac_to_regex: Vec<Vec<usize>> = Vec::new();

        for (i, p) in patterns.iter().enumerate() {
            if let Some(prefix) = pattern::literal_prefix(p) {
                if let Some(pos) = unique_prefixes.iter().position(|x| x == &prefix) {
                    if let Some(group) = ac_to_regex.get_mut(pos) {
                        group.push(i);
                    }
                } else {
                    unique_prefixes.push(prefix);
                    ac_to_regex.push(vec![i]);
                }
            }
        }

        let ac = if unique_prefixes.is_empty() {
            None
        } else {
            let automaton = AhoCorasick::new(&unique_prefixes).map_err(|e| {
                Error::config(format!("failed to build Aho-Corasick automaton: {e}"))
            })?;
            Some(automaton)
        };

        Ok(Self {
            ac,
            regexes,
            ignore_regexes: Vec::new(),
            ac_to_regex,
        })
    }

    /// Build a matcher with both fail patterns and ignore patterns.
    pub fn with_ignoreregex(patterns: &[String], ignoreregex: &[String]) -> Result<Self> {
        let mut matcher = Self::new(patterns)?;
        for (i, pat) in ignoreregex.iter().enumerate() {
            let re = Regex::new(pat).map_err(|e| Error::Regex {
                pattern: format!("ignoreregex[{i}]: {pat}"),
                source: e,
            })?;
            matcher.ignore_regexes.push(re);
        }
        Ok(matcher)
    }

    /// Try to match a log line, returning the extracted IP and pattern index.
    ///
    /// Returns `None` if the line doesn't match any fail pattern, or if it
    /// matches an ignoreregex pattern.
    pub fn try_match(&self, line: &str) -> Option<MatchResult> {
        if let Some(ref ac) = self.ac {
            // Phase 1: AC pre-filter — reject lines without any known prefix.
            let ac_match = ac.find(line)?;
            let primary = self.ac_to_regex.get(ac_match.pattern().as_usize())?;

            // Phase 2: Try only regexes whose AC prefix was found (fast path).
            for &idx in primary {
                if let Some(regex) = self.regexes.get(idx)
                    && let Some(m) = regex.find(line)
                    && let Some(ip) = extract_ip(m.as_str())
                {
                    if self.ignore_regexes.iter().any(|re| re.is_match(line)) {
                        return None;
                    }
                    return Some(MatchResult {
                        ip,
                        pattern_idx: idx,
                    });
                }
            }

            // Fallback: try remaining regexes in order (handles rare cases
            // where multiple AC prefixes appear in the same line, or patterns
            // without an AC prefix).
            for idx in 0..self.regexes.len() {
                if primary.contains(&idx) {
                    continue;
                }
                if let Some(regex) = self.regexes.get(idx)
                    && let Some(m) = regex.find(line)
                    && let Some(ip) = extract_ip(m.as_str())
                {
                    if self.ignore_regexes.iter().any(|re| re.is_match(line)) {
                        return None;
                    }
                    return Some(MatchResult {
                        ip,
                        pattern_idx: idx,
                    });
                }
            }

            None
        } else {
            // No AC automaton — try all regexes sequentially.
            for (idx, regex) in self.regexes.iter().enumerate() {
                if let Some(m) = regex.find(line)
                    && let Some(ip) = extract_ip(m.as_str())
                {
                    if self.ignore_regexes.iter().any(|re| re.is_match(line)) {
                        return None;
                    }
                    return Some(MatchResult {
                        ip,
                        pattern_idx: idx,
                    });
                }
            }
            None
        }
    }

    /// Number of patterns in this matcher.
    pub fn pattern_count(&self) -> usize {
        self.regexes.len()
    }
}

/// Extract an IP address from a regex match span.
///
/// Splits on characters that cannot appear in any IP address (v4 or v6),
/// then scans tokens from the right.  In typical log patterns `<HOST>`
/// appears near the end of the match, so the IP is found in 1–2 checks.
///
/// This handles IPs that are not space-delimited, e.g. `[185.0.0.1]`.
fn extract_ip(span: &str) -> Option<IpAddr> {
    for token in span.rsplit(|c: char| !c.is_ascii_hexdigit() && c != '.' && c != ':') {
        if token.len() >= 2
            && let Ok(ip) = token.parse::<IpAddr>()
        {
            return Some(ip);
        }
    }
    None
}
