//! Tests for the regex testing tool.
//!
//! Note: `test_pattern` and `test_patterns` call `std::process::exit(1)` on
//! invalid patterns, so we can't test the error path without a subprocess.
//! We test the underlying matcher logic that they wrap.

use crate::matcher::JailMatcher;

#[test]
fn test_pattern_match() {
    let m = JailMatcher::new(&[r"Failed password for .* from <HOST>".to_string()]).unwrap();
    let line = "sshd[123]: Failed password for root from 10.0.0.1 port 22";
    let result = m.try_match(line).unwrap();
    assert_eq!(result.ip.to_string(), "10.0.0.1");
}

#[test]
fn test_pattern_no_match() {
    let m = JailMatcher::new(&[r"Failed password for .* from <HOST>".to_string()]).unwrap();
    let line = "sshd[123]: Accepted password for user from 10.0.0.1 port 22";
    assert!(m.try_match(line).is_none());
}

#[test]
fn test_patterns_multiple_first_wins() {
    let patterns = vec![
        r"Failed password .* from <HOST>".to_string(),
        r"Invalid user .* from <HOST>".to_string(),
    ];
    let m = JailMatcher::new(&patterns).unwrap();

    let line = "Invalid user admin from 1.2.3.4 port 22";
    let result = m.try_match(line).unwrap();
    assert_eq!(result.ip.to_string(), "1.2.3.4");
    assert_eq!(result.pattern_idx, 1);
}

#[test]
fn test_patterns_no_match_any() {
    let patterns = vec![
        r"Failed .* from <HOST>".to_string(),
        r"Invalid .* from <HOST>".to_string(),
    ];
    let m = JailMatcher::new(&patterns).unwrap();
    let line = "Accepted password for user from 10.0.0.1 port 22";
    assert!(m.try_match(line).is_none());
}
