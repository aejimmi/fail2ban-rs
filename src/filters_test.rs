//! Tests for built-in filter templates.

use crate::filters;
use crate::pattern::expand_host;

#[test]
fn find_sshd() {
    let f = filters::find("sshd").unwrap();
    assert_eq!(f.name, "sshd");
    assert!(!f.patterns.is_empty());
}

#[test]
fn find_nonexistent() {
    assert!(filters::find("nonexistent").is_none());
}

#[test]
fn all_filters_have_host() {
    for f in filters::FILTERS {
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
    for f in filters::FILTERS {
        for pattern in f.patterns {
            let expanded = expand_host(pattern);
            assert!(
                expanded.is_ok(),
                "filter {} pattern failed to expand: {} — {}",
                f.name,
                pattern,
                expanded.unwrap_err()
            );
            let expanded = expanded.unwrap();
            let re = regex::Regex::new(&expanded);
            assert!(
                re.is_ok(),
                "filter {} expanded pattern failed to compile: {} — {}",
                f.name,
                expanded,
                re.unwrap_err()
            );
        }
    }
}

#[test]
fn gen_config_sshd() {
    let f = filters::find("sshd").unwrap();
    let toml = filters::gen_config(f);
    assert!(toml.contains("[jail.sshd]"));
    assert!(toml.contains("/var/log/auth.log"));
    assert!(toml.contains("syslog"));
    assert!(toml.contains("<HOST>"));
}

#[test]
fn gen_config_all_services() {
    for f in filters::FILTERS {
        let toml = filters::gen_config(f);
        assert!(
            toml.contains(&format!("[jail.{}]", f.name)),
            "gen_config missing jail header for {}",
            f.name
        );
    }
}

#[test]
fn filter_count() {
    assert_eq!(filters::FILTERS.len(), 19, "expected 19 built-in filters");
}

#[test]
fn sshd_patterns_match_real_lines() {
    let f = filters::find("sshd").unwrap();
    let expanded = expand_host(f.patterns[0]).unwrap();
    let re = regex::Regex::new(&expanded).unwrap();

    let line = "sshd[1234]: Failed password for root from 192.168.1.100 port 22";
    assert!(re.is_match(line), "sshd pattern should match: {line}");
}
