//! Built-in filter patterns for common services.
//!
//! Filter definitions are grouped into category modules ([`auth`], [`web`],
//! [`mail`], …) as static data tables. [`FILTERS`] chains those tables into a
//! single registry used by `fail2ban-rs gen-config --service <name>` to
//! generate jail configurations without manual pattern writing.

mod auth;
mod db;
mod ftp;
mod mail;
mod misc;
mod voip;
mod vpn;
mod web;

/// A built-in filter template for a service.
pub struct FilterTemplate {
    /// Service identifier (e.g. "sshd").
    pub name: &'static str,
    /// Human-readable description.
    pub description: &'static str,
    /// Default log file path.
    pub log_path: &'static str,
    /// Date format preset.
    pub date_format: &'static str,
    /// Regex patterns with `<HOST>` placeholder.
    pub patterns: &'static [&'static str],
}

/// Concrete iterator over the flattened registry.
type FilterIter =
    std::iter::Flatten<std::iter::Copied<std::slice::Iter<'static, &'static [FilterTemplate]>>>;

/// Registry of built-in filters, backed by the per-category data tables.
///
/// This is a zero-cost `Copy` view over the category slices so that callers can
/// keep iterating it directly (`for f in FILTERS`, `FILTERS.iter()`) exactly as
/// they would a plain `&[FilterTemplate]`.
#[derive(Clone, Copy)]
pub struct FilterList {
    groups: &'static [&'static [FilterTemplate]],
}

impl FilterList {
    /// Iterate every filter template in the registry.
    pub fn iter(&self) -> FilterIter {
        (*self).into_iter()
    }

    /// Total number of filter templates across all categories.
    #[must_use]
    pub fn len(&self) -> usize {
        self.groups.iter().map(|g| g.len()).sum()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl IntoIterator for FilterList {
    type Item = &'static FilterTemplate;
    type IntoIter = FilterIter;

    fn into_iter(self) -> Self::IntoIter {
        self.groups.iter().copied().flatten()
    }
}

impl IntoIterator for &FilterList {
    type Item = &'static FilterTemplate;
    type IntoIter = FilterIter;

    fn into_iter(self) -> Self::IntoIter {
        (*self).into_iter()
    }
}

/// All built-in filters, chained from the per-category data tables.
pub const FILTERS: FilterList = FilterList {
    groups: &[
        auth::FILTERS,
        web::FILTERS,
        mail::FILTERS,
        ftp::FILTERS,
        db::FILTERS,
        vpn::FILTERS,
        voip::FILTERS,
        misc::FILTERS,
    ],
};

/// Look up a filter template by name.
pub fn find(name: &str) -> Option<&'static FilterTemplate> {
    FILTERS.iter().find(|f| f.name == name)
}

/// Generate a TOML jail configuration for a service.
pub fn gen_config(template: &FilterTemplate) -> String {
    use std::fmt::Write;
    let mut out = format!("[jail.{}]\n", template.name);
    let _ = writeln!(out, "# {}", template.description);
    let _ = writeln!(out, "log_path = \"{}\"", template.log_path);
    let _ = writeln!(out, "date_format = \"{}\"", template.date_format);
    out.push_str("filter = [\n");
    for pattern in template.patterns {
        let _ = writeln!(out, "    '{pattern}',");
    }
    out.push_str("]\n");
    out
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::needless_pass_by_value,
    clippy::redundant_closure_for_method_calls
)]
pub(crate) mod test_util {
    use super::*;
    use crate::detect::matcher::JailMatcher;
    use std::net::IpAddr;

    /// Build a JailMatcher from a named filter and assert it extracts the expected IP.
    pub fn assert_filter_matches(filter_name: &str, line: &str, expected_ip: &str) {
        let f = find(filter_name).unwrap_or_else(|| panic!("filter not found: {filter_name}"));
        let patterns: Vec<String> = f.patterns.iter().map(|p| p.to_string()).collect();
        let m = JailMatcher::new(&patterns).unwrap();
        let result = m.try_match(line);
        let expected: IpAddr = expected_ip.parse().unwrap();
        assert!(
            result.is_some(),
            "filter '{filter_name}' should match line: {line}"
        );
        assert_eq!(
            result.unwrap().ip,
            expected,
            "filter '{filter_name}' extracted wrong IP from: {line}"
        );
    }

    /// Assert that a line does NOT match a filter.
    pub fn assert_filter_no_match(filter_name: &str, line: &str) {
        let f = find(filter_name).unwrap();
        let patterns: Vec<String> = f.patterns.iter().map(|p| p.to_string()).collect();
        let m = JailMatcher::new(&patterns).unwrap();
        assert!(
            m.try_match(line).is_none(),
            "filter '{filter_name}' should NOT match line: {line}"
        );
    }
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::needless_pass_by_value
)]
mod mod_test;
