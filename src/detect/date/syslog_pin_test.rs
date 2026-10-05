//! Pinned behaviour: scanner semantics, DST transitions and year rollover,
//! using deterministic synthetic zones (independent of the host timezone).

use super::syslog_test::{CHATHAM, EASTERN, QUARTER, TestZone, new_parse_at, old_parse_at, utc};
use super::*;

fn fields(month: [u8; 3], day: u32, hour: u32, min: u32, sec: u32) -> SyslogFields {
    SyslogFields {
        month,
        day,
        hour,
        min,
        sec,
    }
}

/// Parse in US Eastern with "now" at the end of 2026 (no rollover for 2026).
fn eastern(cache: &SyslogCache, line: &str) -> Option<i64> {
    let now = utc(2026, 12, 31, 12, 0, 0);
    let tz = TestZone(&EASTERN);
    let got = new_parse_at(cache, &tz, now, line);
    assert_eq!(
        got,
        old_parse_at(&tz, now, line),
        "oracle mismatch: {line:?}"
    );
    got
}

#[test]
fn test_scan_leftmost_match_with_bad_month_is_final() {
    let line = b"Xyz 15 10:30:00 then Jan 15 10:30:00";
    assert_eq!(scan(line), Scan::Found(fields(*b"Xyz", 15, 10, 30, 0)));
    let parser = crate::detect::date::DateParser::new(crate::detect::date::DateFormat::Syslog)
        .expect("syslog parser");
    assert_eq!(
        parser.parse_line("Xyz 15 10:30:00 then Jan 15 10:30:00"),
        None
    );
}

#[test]
fn test_scan_padding_and_position() {
    assert_eq!(
        scan(b"Oct  5 01:02:03"),
        Scan::Found(fields(*b"Oct", 5, 1, 2, 3))
    );
    assert_eq!(
        scan(b"Oct 05 01:02:03"),
        Scan::Found(fields(*b"Oct", 5, 1, 2, 3))
    );
    assert_eq!(
        scan(b"<13>Oct 5\t01:02:03"),
        Scan::Found(fields(*b"Oct", 5, 1, 2, 3))
    );
    assert_eq!(
        scan(b"Jan 123 10:30:00 Feb  1 10:00:00"),
        Scan::Found(fields(*b"Feb", 1, 10, 0, 0))
    );
}

#[test]
fn test_scan_rejects_malformed() {
    for line in [
        &b""[..],
        b"Jan",
        b"Jan 5",
        b"Jan5 10:30:00",
        b"Jan 5 1:30:00",
        b"JAN 5 10:30:00",
    ] {
        assert_eq!(
            scan(line),
            Scan::Absent,
            "{:?}",
            String::from_utf8_lossy(line)
        );
    }
}

#[test]
fn test_scan_non_ascii_defers_to_regex() {
    assert_eq!(scan("Jan\u{a0}5 10:30:00".as_bytes()), Scan::NeedsRegex);
    assert_eq!(scan("Jan \u{663} 10:30:00".as_bytes()), Scan::NeedsRegex);
    // Non-ASCII bytes outside any candidate match do not trigger the fallback.
    assert_eq!(
        scan("Jan  5 10:30:00 user \u{e9}".as_bytes()),
        Scan::Found(fields(*b"Jan", 5, 10, 30, 0))
    );
}

#[test]
fn test_syslog_dst_spring_forward_gap_falls_back_to_utc() {
    let cache = SyslogCache::default();
    assert_eq!(
        eastern(&cache, "Mar  8 02:30:00 x"),
        Some(utc(2026, 3, 8, 2, 30, 0))
    );
}

#[test]
fn test_syslog_dst_fall_back_overlap_falls_back_to_utc() {
    let cache = SyslogCache::default();
    assert_eq!(
        eastern(&cache, "Nov  1 01:30:00 x"),
        Some(utc(2026, 11, 1, 1, 30, 0))
    );
}

#[test]
fn test_syslog_dst_cached_offset_not_reused_across_spring_forward() {
    let cache = SyslogCache::default();
    // EST (-5h) before, EDT (-4h) after; each warms the cache for its hour.
    assert_eq!(
        eastern(&cache, "Mar  8 01:59:59 x"),
        Some(utc(2026, 3, 8, 6, 59, 59))
    );
    assert_eq!(
        eastern(&cache, "Mar  8 03:00:00 x"),
        Some(utc(2026, 3, 8, 7, 0, 0))
    );
    assert_eq!(
        eastern(&cache, "Mar  8 01:00:00 x"),
        Some(utc(2026, 3, 8, 6, 0, 0))
    );
    assert_eq!(
        eastern(&cache, "Mar  8 03:59:59 x"),
        Some(utc(2026, 3, 8, 7, 59, 59))
    );
}

#[test]
fn test_syslog_dst_cached_offset_not_reused_across_fall_back() {
    let cache = SyslogCache::default();
    assert_eq!(
        eastern(&cache, "Nov  1 00:59:59 x"),
        Some(utc(2026, 11, 1, 4, 59, 59))
    );
    assert_eq!(
        eastern(&cache, "Nov  1 02:00:00 x"),
        Some(utc(2026, 11, 1, 7, 0, 0))
    );
    assert_eq!(
        eastern(&cache, "Nov  1 00:00:00 x"),
        Some(utc(2026, 11, 1, 4, 0, 0))
    );
}

#[test]
fn test_syslog_dst_non_hour_aligned_transition() {
    let cache = SyslogCache::default();
    let tz = TestZone(&CHATHAM);
    let now = utc(2026, 12, 31, 12, 0, 0);
    let parse = |line: &str| {
        let got = new_parse_at(&cache, &tz, now, line);
        assert_eq!(
            got,
            old_parse_at(&tz, now, line),
            "oracle mismatch: {line:?}"
        );
        got
    };
    // Gap is [02:45, 03:45) local on Sep 27; both hours straddle it.
    let local = |h, m, s| utc(2026, 9, 27, h, m, s);
    assert_eq!(parse("Sep 27 02:44:59 x"), Some(local(2, 44, 59) - 45_900));
    assert_eq!(parse("Sep 27 02:45:00 x"), Some(local(2, 45, 0)));
    assert_eq!(parse("Sep 27 02:00:00 x"), Some(local(2, 0, 0) - 45_900));
    assert_eq!(parse("Sep 27 03:44:59 x"), Some(local(3, 44, 59)));
    assert_eq!(parse("Sep 27 03:45:00 x"), Some(local(3, 45, 0) - 49_500));
}

#[test]
fn test_syslog_dst_shift_inside_one_hour_is_not_cached() {
    let cache = SyslogCache::default();
    let tz = TestZone(&QUARTER);
    let now = utc(2026, 12, 31, 12, 0, 0);
    let local = |h, m, s| utc(2026, 5, 10, h, m, s);
    // Both ends of hour 02 are unambiguous, but with different offsets.
    for (line, want) in [
        ("May 10 02:00:00 x", local(2, 0, 0) - 3_600),
        ("May 10 02:59:59 x", local(2, 59, 59) - 4_500),
        ("May 10 02:20:00 x", local(2, 20, 0)),
        ("May 10 02:14:59 x", local(2, 14, 59) - 3_600),
        ("May 10 02:30:00 x", local(2, 30, 0) - 4_500),
    ] {
        assert_eq!(new_parse_at(&cache, &tz, now, line), Some(want), "{line:?}");
        assert_eq!(old_parse_at(&tz, now, line), Some(want), "oracle {line:?}");
    }
}

#[test]
fn test_syslog_year_rollover_threshold() {
    let cache = SyslogCache::default();
    let tz = TestZone(&EASTERN);
    // 2027-01-01 00:30 local (EST).
    let now = utc(2027, 1, 1, 5, 30, 0);
    let check = |line: &str, want: i64| {
        assert_eq!(new_parse_at(&cache, &tz, now, line), Some(want), "{line:?}");
        assert_eq!(old_parse_at(&tz, now, line), Some(want), "oracle {line:?}");
    };
    check("Dec 31 23:59:59 x", utc(2027, 1, 1, 4, 59, 59));
    // Exactly now + 1 day stays in the current year; one second later rolls.
    check("Jan  2 00:30:00 x", now + DAY);
    check("Jan  2 00:30:01 x", utc(2026, 1, 2, 5, 30, 1));
}

#[test]
fn test_syslog_feb29_year_handling() {
    let tz = TestZone(&EASTERN);
    let cases = [
        (utc(2028, 3, 15, 0, 0, 0), true),  // leap year, already past
        (utc(2028, 1, 15, 0, 0, 0), false), // leap year, rolls to 2027: invalid
        (utc(2026, 6, 1, 0, 0, 0), false),  // non-leap current year
        (utc(2029, 1, 15, 0, 0, 0), false), // non-leap; never tries 2028
    ];
    for (now, valid) in cases {
        let cache = SyslogCache::default();
        let line = "Feb 29 12:00:00 x";
        let got = new_parse_at(&cache, &tz, now, line);
        assert_eq!(got.is_some(), valid, "now={now}");
        assert_eq!(got, old_parse_at(&tz, now, line), "now={now}");
    }
}

#[test]
fn test_syslog_cache_packs_negative_offsets() {
    let cache = SyslogCache::default();
    let tz = chrono::FixedOffset::west_opt(36_000).expect("valid offset");
    let now = utc(2026, 6, 1, 0, 0, 0);
    let f = fields(*b"May", 1, 10, 0, 0);
    let want = Some(utc(2026, 5, 1, 20, 0, 0));
    assert_eq!(cache.resolve_at(&tz, &f, now, 2026), want);
    // Second call is served from the cache.
    assert_eq!(
        cache.cached_offset(utc(2026, 5, 1, 10, 0, 0) / 3600, now),
        Some(-36_000)
    );
    assert_eq!(cache.resolve_at(&tz, &f, now, 2026), want);
}

#[test]
fn test_syslog_cache_entry_expires_next_second() {
    let cache = SyslogCache::default();
    let tz = chrono::FixedOffset::east_opt(3_600).expect("valid offset");
    let now = utc(2026, 6, 1, 0, 0, 0);
    let hour = utc(2026, 5, 1, 10, 0, 0) / 3600;
    let f = fields(*b"May", 1, 10, 0, 0);
    assert_eq!(
        cache.resolve_at(&tz, &f, now, 2026),
        Some(utc(2026, 5, 1, 9, 0, 0))
    );
    assert_eq!(cache.cached_offset(hour, now), Some(3_600));
    // Re-verified against chrono each wall-clock second (picks up TZ changes).
    assert_eq!(cache.cached_offset(hour, now + 1), None);
    assert_eq!(cache.cached_offset(hour + 1, now), None);
}
