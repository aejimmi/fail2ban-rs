//! Fast matching engine for log lines.
//!
//! Phase 1: Aho-Corasick automaton over deduplicated literal prefixes rejects
//! non-matching lines in ~10ns.
//! Phase 2: AC-guided regex selection — only tries regexes whose literal
//! prefix was found in the line, skipping impossible patterns.
//! IP extraction uses `find()` (DFA) plus positional string ops to extract
//! the IP from the `<HOST>` location, falling back to `captures()` only for
//! patterns with ambiguous literal context.

use std::net::IpAddr;

use aho_corasick::AhoCorasick;
use regex::Regex;

use crate::detect::extract::{
    extract_ip_after_literal, extract_ip_at_start, extract_ip_before_literal, normalize_mapped,
};
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
        if let Some(ref ac) = self.ac {
            if let Some(ac_match) = ac.find(line)
                && let Some(primary) = self.ac_to_regex.get(ac_match.pattern().as_usize())
            {
                // Phase 2: Try only regexes whose AC prefix was found (fast path).
                for &idx in primary {
                    if let Some(result) = self.match_regex(idx, line) {
                        return Some(result);
                    }
                }

                // Fallback: try remaining regexes in order (handles cases
                // where multiple AC prefixes appear in the same line, or
                // patterns without an AC prefix).
                for idx in 0..self.regexes.len() {
                    if primary.contains(&idx) {
                        continue;
                    }
                    if let Some(result) = self.match_regex(idx, line) {
                        return Some(result);
                    }
                }

                return None;
            }

            // AC found no known prefix — still try patterns that have no AC
            // entry (they were never added to the automaton, so AC can't
            // filter them). Patterns that DO have an AC entry are skipped: the
            // line clearly lacks their required literal. `non_ac_regexes` is
            // precomputed, so this common path allocates nothing.
            for &idx in &self.non_ac_regexes {
                if let Some(result) = self.match_regex(idx, line) {
                    return Some(result);
                }
            }
            None
        } else {
            // No AC automaton — try all regexes sequentially.
            for idx in 0..self.regexes.len() {
                if let Some(result) = self.match_regex(idx, line) {
                    return Some(result);
                }
            }
            None
        }
    }

    /// Try a single regex against `line`.
    ///
    /// Fast path: `find()` (DFA) for match/reject, then positional string
    /// ops to extract the IP from the `<HOST>` location in the match span.
    /// Slow path: `captures()` for patterns with ambiguous literal context.
    fn match_regex(&self, idx: usize, line: &str) -> Option<MatchResult> {
        let regex = self.regexes.get(idx)?;
        let extractor = self.extractors.get(idx)?;

        let ip = match extractor {
            HostExtractor::AtStart => {
                let m = regex.find(line)?;
                extract_ip_at_start(m.as_str())?
            }
            HostExtractor::AfterLiteral(lit) => {
                let m = regex.find(line)?;
                extract_ip_after_literal(m.as_str(), lit)?
            }
            HostExtractor::BeforeLiteral(lit) => {
                let m = regex.find(line)?;
                extract_ip_before_literal(m.as_str(), lit)?
            }
            HostExtractor::Captures => {
                let caps = regex.captures(line)?;
                let host_text = caps.name("host")?.as_str();
                let ip = host_text.parse::<IpAddr>().ok()?;
                normalize_mapped(ip)
            }
        };

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
