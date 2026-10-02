//! Fast matching engine for log lines.
//!
//! Phase 1: Aho-Corasick checks deduplicated mandatory regex literals.
//! Phase 2: Eligible regexes run in their original order, including overlapping
//! literal matches and patterns without a mandatory literal.
//! IP extraction uses `find()` (DFA) plus positional string ops to extract
//! the IP from the `<HOST>` location, falling back to `captures()` only for
//! patterns with ambiguous literal context.

use std::net::IpAddr;

use aho_corasick::AhoCorasick;
use regex::Regex;

use crate::detect::extract::normalize_mapped;
use crate::detect::pattern::{self, HostExtractor};
use crate::error::{Error, Result};

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
    /// Per-pattern extraction strategy.
    extractors: Vec<HostExtractor>,
    /// Compiled ignoreregex patterns — matched lines are suppressed.
    ignore_regexes: Vec<Regex>,
    /// Maps each AC pattern slot → regex indices to try. Deduplicated:
    /// patterns sharing the same literal prefix are grouped under one slot.
    ac_to_regex: Vec<Vec<usize>>,
    /// Regex indices that have NO Aho-Corasick prefix. Precomputed so the hot
    /// path (every non-matching line) never allocates. These are the only
    /// patterns worth trying when AC finds no known literal.
    non_ac_regexes: Vec<usize>,
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

        // Determine extraction strategy for each pattern.
        let extractors: Vec<HostExtractor> = patterns
            .iter()
            .map(|p| pattern::host_extractor(p))
            .collect();

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

        // Precompute the set of regexes with no AC prefix (owned, allocated
        // once) so `try_match` never builds it per line.
        let mut ac_covered = vec![false; regexes.len()];
        for group in &ac_to_regex {
            for &i in group {
                if let Some(flag) = ac_covered.get_mut(i) {
                    *flag = true;
                }
            }
        }
        let non_ac_regexes: Vec<usize> = ac_covered
            .iter()
            .enumerate()
            .filter_map(|(i, covered)| (!covered).then_some(i))
            .collect();

        Ok(Self {
            ac,
            regexes,
            extractors,
            ignore_regexes: Vec::new(),
            ac_to_regex,
            non_ac_regexes,
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
        // A single regex already has its own literal acceleration. Avoid
        // duplicating that work, and keep patterns without literals simple.
        if self.regexes.len() == 1 {
            return self.match_regex(0, line);
        }
        let Some(ac) = &self.ac else {
            for idx in 0..self.regexes.len() {
                if let Some(result) = self.match_regex(idx, line) {
                    return Some(result);
                }
            }
            return None;
        };
        let mut found = ac.find_overlapping_iter(line);
        let Some(first) = found.next() else {
            for &idx in &self.non_ac_regexes {
                if let Some(result) = self.match_regex(idx, line) {
                    return Some(result);
                }
            }
            return None;
        };
        // Keep the common small-jail path allocation-free. Larger custom
        // filters use a scratch vector rather than limiting pattern coverage.
        let mut local = [false; 128];
        let mut large = Vec::new();
        let candidates = if let Some(short) = local.get_mut(..self.regexes.len()) {
            short
        } else {
            large.resize(self.regexes.len(), false);
            large.as_mut_slice()
        };
        {
            for &idx in &self.non_ac_regexes {
                if let Some(candidate) = candidates.get_mut(idx) {
                    *candidate = true;
                }
            }
            // Overlapping literals can enable different regexes at the same
            // position. A first-hit-only search cannot establish precedence.
            let mut remaining = self.ac_to_regex.len();
            for hit in std::iter::once(first).chain(found) {
                if let Some(indices) = self.ac_to_regex.get(hit.pattern().as_usize()) {
                    // Each regex owns one mandatory literal. A previously
                    // enabled first entry therefore means this whole group
                    // was already visited, even on a line with many repeats.
                    if indices
                        .first()
                        .and_then(|idx| candidates.get(*idx))
                        .copied()
                        .unwrap_or(false)
                    {
                        continue;
                    }
                    for &idx in indices {
                        if let Some(candidate) = candidates.get_mut(idx) {
                            *candidate = true;
                        }
                    }
                    remaining = remaining.saturating_sub(1);
                    if remaining == 0 {
                        break;
                    }
                }
            }
        }
        for (idx, enabled) in candidates.iter().enumerate() {
            if *enabled && let Some(result) = self.match_regex(idx, line) {
                return Some(result);
            }
        }
        None
    }

    /// Try a single regex against `line`.
    ///
    /// Fast path: `find()` (DFA) for match/reject, then positional string
    /// ops to extract the IP from the `<HOST>` location in the match span.
    /// Slow path: `captures()` for patterns with ambiguous literal context.
    fn match_regex(&self, idx: usize, line: &str) -> Option<MatchResult> {
        let regex = self.regexes.get(idx)?;
        let extractor = self.extractors.get(idx)?;

        let captures_ip = || {
            let caps = regex.captures(line)?;
            let ip = caps.name("host")?.as_str().parse::<IpAddr>().ok()?;
            Some(normalize_mapped(ip))
        };
        let ip = match extractor {
            HostExtractor::AtStart | HostExtractor::AfterLiteral(_) => {
                let span = regex.find(line)?.as_str();
                let start = match extractor {
                    HostExtractor::AfterLiteral(lit) => {
                        // A wildcard may repeat the delimiter. Captures decide
                        // which occurrence belongs to HOST in that case.
                        let start = span.find(lit.as_str())?;
                        if span.rfind(lit.as_str()) != Some(start) {
                            return self.finish_capture(idx, line);
                        }
                        start + lit.len()
                    }
                    _ => 0,
                };
                let tail = span.get(start..)?;
                let end = tail
                    .find(|c: char| !c.is_ascii_hexdigit() && c != '.' && c != ':')
                    .unwrap_or(tail.len());
                normalize_mapped(tail.get(..end)?.parse::<IpAddr>().ok()?)
            }
            HostExtractor::BeforeLiteral(lit) => {
                let span = regex.find(line)?.as_str();
                let end = span.find(lit.as_str())?;
                if span.rfind(lit.as_str()) != Some(end) {
                    return self.finish_capture(idx, line);
                }
                let before = span.get(..end)?;
                let start = before
                    .rfind(|c: char| !c.is_ascii_hexdigit() && c != '.' && c != ':')
                    .map_or(0, |i| i + 1);
                normalize_mapped(before.get(start..)?.parse::<IpAddr>().ok()?)
            }
            HostExtractor::Captures => captures_ip()?,
        };

        if self.ignore_regexes.iter().any(|re| re.is_match(line)) {
            return None;
        }

        Some(MatchResult {
            ip,
            pattern_idx: idx,
        })
    }

    /// Capture fallback for a repeated positional delimiter.
    fn finish_capture(&self, idx: usize, line: &str) -> Option<MatchResult> {
        let caps = self.regexes.get(idx)?.captures(line)?;
        let ip = normalize_mapped(caps.name("host")?.as_str().parse::<IpAddr>().ok()?);
        if self.ignore_regexes.iter().any(|re| re.is_match(line)) {
            return None;
        }
        Some(MatchResult {
            ip,
            pattern_idx: idx,
        })
    }

    /// Number of patterns in this matcher.
    pub fn pattern_count(&self) -> usize {
        self.regexes.len()
    }
}

#[cfg(test)]
#[path = "matcher_test.rs"]
mod matcher_test;

// IP-extraction tests exercise the extract functions through `JailMatcher`
// (they build a matcher and inspect the extracted IP), so they live alongside
// the matcher tests rather than under `extract`.
#[cfg(test)]
#[path = "extract_test.rs"]
mod extract_test;
