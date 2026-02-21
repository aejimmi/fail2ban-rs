//! Two-phase matching engine for log lines.
//!
//! Phase 1: Aho-Corasick automaton over literal prefixes rejects ~99% of
//! non-matching lines in ~10ns.
//! Phase 2: `RegexSet` identifies which pattern matched (single pass).
//! Phase 3: Individual `Regex` extracts the IP from the matched pattern.

use std::net::IpAddr;

use aho_corasick::AhoCorasick;
use regex::{Regex, RegexSet};

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
    /// RegexSet for identifying which pattern matched.
    regex_set: RegexSet,
    /// Individual compiled regexes for IP extraction.
    regexes: Vec<Regex>,
    /// Whether AC pre-filtering is active.
    has_ac: bool,
    /// Compiled ignoreregex patterns — matched lines are suppressed.
    ignore_regexes: Vec<Regex>,
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

        // Build individual regexes for IP extraction.
        let regexes: Vec<Regex> = expanded
            .iter()
            .enumerate()
            .map(|(i, p)| {
                Regex::new(p).map_err(|e| Error::Regex {
                    pattern: patterns[i].clone(),
                    source: e,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        // Build RegexSet for multi-pattern matching.
        let regex_set = RegexSet::new(&expanded).map_err(|e| Error::Regex {
            pattern: "regex set".to_string(),
            source: e,
        })?;

        // Extract literal prefixes for Aho-Corasick.
        let mut ac_patterns = Vec::new();
        for p in patterns {
            if let Some(prefix) = pattern::literal_prefix(p) {
                ac_patterns.push(prefix);
            }
        }

        let (ac, has_ac) = if ac_patterns.is_empty() {
            (None, false)
        } else {
            let automaton = AhoCorasick::new(&ac_patterns).map_err(|e| {
                Error::config(format!("failed to build Aho-Corasick automaton: {e}"))
            })?;
            (Some(automaton), true)
        };

        Ok(Self {
            ac,
            regex_set,
            regexes,
            has_ac,
            ignore_regexes: Vec::new(),
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
        // Phase 1: Aho-Corasick pre-filter.
        if self.has_ac
            && let Some(ref ac) = self.ac
        {
            ac.find(line)?;
        }

        // Phase 2: RegexSet identifies matching patterns.
        let matches: Vec<usize> = self.regex_set.matches(line).into_iter().collect();
        if matches.is_empty() {
            return None;
        }

        // Phase 3: Extract IP from the first matching pattern.
        for &idx in &matches {
            if let Some(caps) = self.regexes[idx].captures(line)
                && let Some(host) = caps.name("host")
                && let Ok(ip) = host.as_str().parse::<IpAddr>()
            {
                // Check ignoreregex — suppress if any matches.
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

    /// Number of patterns in this matcher.
    pub fn pattern_count(&self) -> usize {
        self.regexes.len()
    }
}
