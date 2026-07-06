use super::*;
use crate::detect::pattern::expand_host;
use std::collections::HashSet;

#[test]
fn find_sshd() {
    let f = find("sshd").expect("sshd filter present");
    assert_eq!(f.name, "sshd");
    assert!(!f.patterns.is_empty());
}

#[test]
fn find_nonexistent() {
    assert!(find("nonexistent").is_none());
}

#[test]
fn all_filters_have_host() {
    for f in FILTERS {
        for pattern in f.patterns {
            assert!(
                pattern.contains("<HOST>"),
                "filter {} pattern missing <HOST>: {}",
                f.name,
                pattern
            );
        }
    }
}

#[test]
fn all_patterns_compile() {
    for f in FILTERS {
        for pattern in f.patterns {
            let expanded = expand_host(pattern).unwrap_or_else(|e| {
                panic!(
                    "filter {} pattern failed to expand: {pattern} — {e}",
                    f.name
                )
            });
            let re = regex::Regex::new(&expanded);
            assert!(
                re.is_ok(),
                "filter {} expanded pattern failed to compile: {expanded}",
                f.name
            );
        }
    }
}

#[test]
fn gen_config_sshd() {
    let f = find("sshd").expect("sshd filter present");
    let toml = gen_config(f);
    assert!(toml.contains("[jail.sshd]"));
    assert!(toml.contains("/var/log/auth.log"));
    assert!(toml.contains("syslog"));
    assert!(toml.contains("<HOST>"));
}

#[test]
fn gen_config_all_services() {
    for f in FILTERS {
        let toml = gen_config(f);
        assert!(
            toml.contains(&format!("[jail.{}]", f.name)),
            "gen_config missing jail header for {}",
            f.name
        );
    }
}

/// The registry length is derived from the category tables — no hand-maintained
/// count. This guards against a category slice being dropped from `FILTERS`.
#[test]
fn registry_length_matches_categories() {
    let category_sum: usize = FILTERS.groups.iter().map(|g| g.len()).sum();
    assert_eq!(FILTERS.len(), category_sum);
    assert_eq!(
        FILTERS.len(),
        88,
        "expected 88 built-in filters across all categories"
    );
}

/// Every filter name must appear exactly once across all category tables.
#[test]
fn no_duplicate_filter_names() {
    let mut seen = HashSet::new();
    for f in FILTERS {
        assert!(seen.insert(f.name), "duplicate filter name: {}", f.name);
    }
    assert_eq!(seen.len(), FILTERS.len());
}
