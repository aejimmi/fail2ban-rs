//! Tests for duration parsing.

use crate::duration::parse_duration;

#[test]
fn plain_integers() {
    assert_eq!(parse_duration("60").unwrap(), 60);
    assert_eq!(parse_duration("3600").unwrap(), 3600);
    assert_eq!(parse_duration("-1").unwrap(), -1);
    assert_eq!(parse_duration("0").unwrap(), 0);
}

#[test]
fn seconds_suffix() {
    assert_eq!(parse_duration("30s").unwrap(), 30);
    assert_eq!(parse_duration("1s").unwrap(), 1);
}

#[test]
fn minutes_suffix() {
    assert_eq!(parse_duration("10m").unwrap(), 600);
    assert_eq!(parse_duration("1m").unwrap(), 60);
    assert_eq!(parse_duration("30m").unwrap(), 1800);
}

#[test]
fn hours_suffix() {
    assert_eq!(parse_duration("1h").unwrap(), 3600);
    assert_eq!(parse_duration("24h").unwrap(), 86400);
}

#[test]
fn days_suffix() {
    assert_eq!(parse_duration("1d").unwrap(), 86400);
    assert_eq!(parse_duration("7d").unwrap(), 604800);
}

#[test]
fn weeks_suffix() {
    assert_eq!(parse_duration("1w").unwrap(), 604800);
    assert_eq!(parse_duration("2w").unwrap(), 1209600);
}

#[test]
fn whitespace_trimmed() {
    assert_eq!(parse_duration("  60  ").unwrap(), 60);
    assert_eq!(parse_duration(" 10m ").unwrap(), 600);
}

#[test]
fn empty_string_error() {
    assert!(parse_duration("").is_err());
    assert!(parse_duration("  ").is_err());
}

#[test]
fn invalid_suffix_error() {
    assert!(parse_duration("10x").is_err());
    assert!(parse_duration("5y").is_err());
}

#[test]
fn invalid_number_error() {
    assert!(parse_duration("abcm").is_err());
    assert!(parse_duration("m").is_err());
}
