use super::*;

#[test]
fn expand_host_ipv4() {
    let expanded = expand_host(r"Failed password for .* from <HOST>").unwrap();
    assert!(expanded.contains("(?P<host>"));
    assert!(!expanded.contains("<HOST>"));
    // Verify the expanded regex compiles
    regex::Regex::new(&expanded).unwrap();
}

#[test]
fn expand_host_with_regex() {
    let expanded = expand_host(r"sshd\[\d+\]: Failed password for .* from <HOST> port").unwrap();
    let re = regex::Regex::new(&expanded).unwrap();
    assert!(re.is_match("sshd[1234]: Failed password for root from 192.168.1.100 port"));
}

#[test]
fn expand_host_ipv6() {
    let expanded = expand_host(r"from <HOST>").unwrap();
    let re = regex::Regex::new(&expanded).unwrap();
    assert!(re.is_match("from 2001:db8::1"));
}

#[test]
fn expand_host_missing() {
    let result = expand_host(r"no host placeholder here");
    assert!(result.is_err());
}

#[test]
fn expand_host_multiple() {
    let result = expand_host(r"<HOST> and <HOST>");
    assert!(result.is_err());
}

#[test]
fn literal_prefix_ssh() {
    let prefix = literal_prefix(r"sshd\[\d+\]: Failed password for .* from <HOST>");
    // Should extract " from " — the longest literal before <HOST>
    let p = prefix.unwrap();
    assert!(p.contains("from ") || p.contains(" from"), "got: {p}");
}

#[test]
fn literal_prefix_simple() {
    let prefix = literal_prefix(r"Connection refused from <HOST>");
    assert_eq!(prefix, Some("Connection refused from ".to_string()));
}

#[test]
fn literal_prefix_none() {
    // Pattern starts with <HOST> — no usable prefix
    let prefix = literal_prefix(r"<HOST> did something");
    assert!(prefix.is_none());
}

#[test]
fn literal_prefix_short() {
    // Prefix too short (< 3 chars)
    let prefix = literal_prefix(r".*<HOST>");
    assert!(prefix.is_none());
}

#[test]
fn literal_prefix_dot_treated_as_meta() {
    // Dot is a regex metacharacter — should split literal segments.
    let prefix = literal_prefix(r"prefix.thing from <HOST>");
    // "prefix" is 6 chars, "thing from " is 11 chars.
    // Dot splits them; "thing from " should be chosen as the longer segment.
    let p = prefix.unwrap();
    assert!(
        p.contains("thing from "),
        "dot should split segments; got: {p}"
    );
}

#[test]
fn expand_host_empty_pattern() {
    let result = expand_host("");
    assert!(result.is_err());
}

#[test]
fn literal_prefix_all_metacharacters() {
    let prefix = literal_prefix(r".*\d+\[\d+\]<HOST>");
    // All chars before <HOST> are metachar or escape sequences — no 3-char literal.
    assert!(prefix.is_none());
}

#[test]
fn literal_prefix_boundary_three_chars() {
    // Exactly 3 chars — the minimum for extract_longest_literal.
    let prefix = literal_prefix(r".*abc<HOST>");
    assert_eq!(prefix, Some("abc".to_string()));
}

#[test]
fn literal_prefix_boundary_two_chars() {
    // 2-char trailing literal after metachar — still returned since the
    // main path doesn't apply the 3-char minimum (only extract_longest_literal does).
    let prefix = literal_prefix(r".*ab<HOST>");
    assert_eq!(prefix, Some("ab".to_string()));
}

#[test]
fn literal_prefix_fallback_too_short() {
    // When the trailing literal is empty, we fall through to extract_longest_literal
    // which requires >= 3 chars. All segments here are < 3 chars.
    let prefix = literal_prefix(r".*a\d+b\w+<HOST>");
    // "a" and "b" are 1 char each — both below the 3-char minimum in extract_longest_literal.
    assert!(prefix.is_none());
}

// ---------------------------------------------------------------------------
// host_extractor selection
// ---------------------------------------------------------------------------

#[test]
fn extractor_at_start_bare() {
    assert!(matches!(
        host_extractor(r"<HOST> - - \["),
        HostExtractor::AtStart
    ));
}

#[test]
fn extractor_at_start_with_caret() {
    assert!(matches!(
        host_extractor(r"^<HOST> .*"),
        HostExtractor::AtStart
    ));
}

#[test]
fn extractor_after_literal() {
    match host_extractor(r"from <HOST> port") {
        HostExtractor::AfterLiteral(lit) => assert_eq!(lit, "from "),
        other => panic!("expected AfterLiteral, got {other:?}"),
    }
}

#[test]
fn extractor_after_literal_with_regex_prefix() {
    // `sshd\[\d+\]: .* from <HOST>` — trailing literal is " from ".
    match host_extractor(r"sshd\[\d+\]: .* from <HOST>") {
        HostExtractor::AfterLiteral(lit) => assert!(
            lit.contains("from "),
            "expected literal containing 'from ', got '{lit}'"
        ),
        other => panic!("expected AfterLiteral, got {other:?}"),
    }
}

#[test]
fn extractor_before_literal() {
    // `user .* <HOST> port` — literal before HOST is " " (1 char, too short),
    // so it falls through to literal after HOST: " port".
    match host_extractor(r"user .* <HOST> port \d+") {
        HostExtractor::BeforeLiteral(lit) => assert_eq!(lit, " port "),
        other => panic!("expected BeforeLiteral, got {other:?}"),
    }
}

#[test]
fn extractor_before_literal_real_sshd() {
    match host_extractor(
        r"sshd\[\d+\]: Connection closed by authenticating user .* <HOST> port \d+",
    ) {
        HostExtractor::BeforeLiteral(lit) => assert_eq!(lit, " port "),
        other => panic!("expected BeforeLiteral, got {other:?}"),
    }
}

#[test]
fn extractor_captures_fallback() {
    // Both literals too short: `\d+ <HOST> \d+` → before=" " after=" ".
    assert!(matches!(
        host_extractor(r"\d+ <HOST> \d+"),
        HostExtractor::Captures
    ));
}

#[test]
fn extractor_after_literal_repeated_keyword() {
    // `from .* from <HOST>` — the literal " from " only appears once in
    // the pattern prefix (the earlier "from" lacks a leading space).
    // AfterLiteral is safe because extract_ip_after_literal's retry loop
    // skips occurrences not followed by a valid IP.
    match host_extractor(r"from .* from <HOST> port \d+") {
        HostExtractor::AfterLiteral(lit) => assert_eq!(lit, " from "),
        other => panic!("expected AfterLiteral, got {other:?}"),
    }
}

#[test]
fn extractor_bracket_encapsulated() {
    // `\[<HOST>\]` — literal before is empty (metachar boundary),
    // literal after is empty (metachar `\]`). Both too short → Captures.
    assert!(matches!(
        host_extractor(r"\[<HOST>\]"),
        HostExtractor::Captures
    ));
}

#[test]
fn extractor_no_host_tag() {
    // Missing <HOST> — should return Captures (graceful fallback).
    assert!(matches!(
        host_extractor(r"no host here"),
        HostExtractor::Captures
    ));
}
