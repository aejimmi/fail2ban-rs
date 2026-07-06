use super::*;

#[test]
fn syslog_format() {
    let parser = DateParser::new(DateFormat::Syslog).unwrap();
    let line = "Jan 15 10:30:00 server sshd[1234]: Failed password";
    let ts = parser.parse_line(line);
    assert!(ts.is_some());
    let ts = ts.unwrap();
    assert!(ts > 0);
}

#[test]
fn syslog_single_digit_day() {
    let parser = DateParser::new(DateFormat::Syslog).unwrap();
    let line = "Feb  3 08:15:22 host kernel: something";
    let ts = parser.parse_line(line);
    assert!(ts.is_some());
}

#[test]
fn iso8601_format() {
    let parser = DateParser::new(DateFormat::Iso8601).unwrap();
    let line = "2024-01-15T10:30:00Z some log message";
    let ts = parser.parse_line(line).unwrap();
    assert!(ts > 0);
    // Should be consistent — parsing twice gives the same result.
    let ts2 = parser.parse_line(line).unwrap();
    assert_eq!(ts, ts2);
}

#[test]
fn iso8601_space_separator() {
    let parser = DateParser::new(DateFormat::Iso8601).unwrap();
    let line = "2024-01-15 10:30:00 some log message";
    let ts = parser.parse_line(line).unwrap();
    // Should produce same result as T-separated.
    let line_t = "2024-01-15T10:30:00 some log message";
    let ts_t = parser.parse_line(line_t).unwrap();
    assert_eq!(ts, ts_t);
}

#[test]
fn epoch_format() {
    let parser = DateParser::new(DateFormat::Epoch).unwrap();
    let line = "1705312200 something happened";
    let ts = parser.parse_line(line).unwrap();
    assert_eq!(ts, 1_705_312_200);
}

#[test]
fn common_log_format() {
    let parser = DateParser::new(DateFormat::Common).unwrap();
    let line = r#"192.168.1.1 - - [15/Jan/2024:10:30:00 +0000] "GET / HTTP/1.1""#;
    let ts = parser.parse_line(line).unwrap();
    assert!(ts > 0);
    // Common and ISO8601 for the same date/time should match.
    let iso_parser = DateParser::new(DateFormat::Iso8601).unwrap();
    let iso_ts = iso_parser.parse_line("2024-01-15T10:30:00 log").unwrap();
    assert_eq!(ts, iso_ts);
}

#[test]
fn no_match_returns_none() {
    let parser = DateParser::new(DateFormat::Iso8601).unwrap();
    let line = "this line has no date";
    assert!(parser.parse_line(line).is_none());
}

#[test]
fn wrong_format_returns_none() {
    let parser = DateParser::new(DateFormat::Epoch).unwrap();
    let line = "Jan 15 10:30:00 syslog format line";
    // Epoch parser looks for 10+ digit number — "10" won't match
    assert!(parser.parse_line(line).is_none());
}

#[test]
fn all_months_parse() {
    let parser = DateParser::new(DateFormat::Syslog).unwrap();
    let months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    for month in months {
        let line = format!("{month} 15 12:00:00 test");
        assert!(
            parser.parse_line(&line).is_some(),
            "failed to parse month: {month}"
        );
    }
}

#[test]
fn invalid_month_returns_none() {
    let parser = DateParser::new(DateFormat::Syslog).unwrap();
    let line = "Xyz 15 10:30:00 server test";
    assert!(parser.parse_line(line).is_none());
}

#[test]
fn epoch_nine_digits_no_match() {
    let parser = DateParser::new(DateFormat::Epoch).unwrap();
    // 9-digit number should NOT match \d{10,}
    let line = "999999999 short";
    assert!(parser.parse_line(line).is_none());
}

#[test]
fn epoch_ten_digits_matches() {
    let parser = DateParser::new(DateFormat::Epoch).unwrap();
    let line = "1000000000 ten digits";
    let ts = parser.parse_line(line).unwrap();
    assert_eq!(ts, 1_000_000_000);
}

#[test]
fn common_invalid_month_returns_none() {
    let parser = DateParser::new(DateFormat::Common).unwrap();
    let line = r#"10.0.0.1 - - [15/Xyz/2024:10:30:00 +0000] "GET /""#;
    assert!(parser.parse_line(line).is_none());
}

#[test]
fn syslog_invalid_time_returns_none() {
    let parser = DateParser::new(DateFormat::Syslog).unwrap();
    // Hour 25 — from_hms_opt returns None.
    let line = "Jan 15 25:30:00 server test";
    assert!(parser.parse_line(line).is_none());
}

// --- Timezone-aware parsing (host-independent) -------------------------------

use chrono::{Local, LocalResult, TimeZone, Timelike};

/// Unix timestamp for a fixed UTC wall-clock instant — host-independent.
fn utc_ts(y: i32, mo: u32, d: u32, h: u32, mi: u32, s: u32) -> i64 {
    chrono::NaiveDate::from_ymd_opt(y, mo, d)
        .unwrap()
        .and_hms_opt(h, mi, s)
        .unwrap()
        .and_utc()
        .timestamp()
}

#[test]
fn common_log_applies_positive_offset() {
    let parser = DateParser::new(DateFormat::Common).unwrap();
    let line = r#"1.2.3.4 - - [15/Jan/2024:10:30:00 +0500] "GET / HTTP/1.1""#;
    let ts = parser.parse_line(line).unwrap();
    // 10:30:00 at +0500 is 05:30:00 UTC.
    assert_eq!(ts, utc_ts(2024, 1, 15, 5, 30, 0));
}

#[test]
fn common_log_applies_negative_offset() {
    let parser = DateParser::new(DateFormat::Common).unwrap();
    let line = r#"1.2.3.4 - - [15/Jan/2024:10:30:00 -0300] "GET / HTTP/1.1""#;
    let ts = parser.parse_line(line).unwrap();
    // 10:30:00 at -0300 is 13:30:00 UTC.
    assert_eq!(ts, utc_ts(2024, 1, 15, 13, 30, 0));
}

#[test]
fn common_log_no_offset_is_utc() {
    let parser = DateParser::new(DateFormat::Common).unwrap();
    let line = r#"1.2.3.4 - - [15/Jan/2024:10:30:00] "GET / HTTP/1.1""#;
    let ts = parser.parse_line(line).unwrap();
    assert_eq!(ts, utc_ts(2024, 1, 15, 10, 30, 0));
}

#[test]
fn iso8601_applies_offset_and_z() {
    let parser = DateParser::new(DateFormat::Iso8601).unwrap();
    assert_eq!(
        parser.parse_line("2024-01-15T10:30:00Z log").unwrap(),
        utc_ts(2024, 1, 15, 10, 30, 0)
    );
    assert_eq!(
        parser.parse_line("2024-01-15T10:30:00+05:00 log").unwrap(),
        utc_ts(2024, 1, 15, 5, 30, 0)
    );
    assert_eq!(
        parser.parse_line("2024-01-15T10:30:00-03:00 log").unwrap(),
        utc_ts(2024, 1, 15, 13, 30, 0)
    );
}

#[test]
fn iso8601_offset_with_fractional_seconds() {
    let parser = DateParser::new(DateFormat::Iso8601).unwrap();
    let ts = parser
        .parse_line("2024-01-15T10:30:00.123456+05:00 log")
        .unwrap();
    assert_eq!(ts, utc_ts(2024, 1, 15, 5, 30, 0));
}

#[test]
fn iso8601_naive_unchanged() {
    let parser = DateParser::new(DateFormat::Iso8601).unwrap();
    let ts = parser.parse_line("2024-01-15T10:30:00 log").unwrap();
    assert_eq!(ts, utc_ts(2024, 1, 15, 10, 30, 0));
}

#[test]
fn syslog_uses_local_time() {
    let parser = DateParser::new(DateFormat::Syslog).unwrap();
    // Build the line from a recent local instant so the year-rollover
    // correction never triggers, then derive the expected value with the
    // same Local offset lookup — host-independent.
    let now = Local::now();
    let line = format!("{} host sshd: test", now.format("%b %e %H:%M:%S"));
    let ts = parser.parse_line(&line).unwrap();

    let naive = now.naive_local().with_nanosecond(0).unwrap();
    let expected = match Local.from_local_datetime(&naive) {
        LocalResult::Single(t) => t.timestamp(),
        _ => naive.and_utc().timestamp(),
    };
    assert_eq!(ts, expected);
}

#[test]
fn syslog_year_rollover_future_date() {
    let parser = DateParser::new(DateFormat::Syslog).unwrap();
    let now = Local::now();
    // A syslog date five days ahead of "now" must be read as last year's
    // occurrence, landing it in the past rather than the future.
    let future = now + chrono::Duration::days(5);
    let line = format!("{} host sshd: x", future.format("%b %e %H:%M:%S"));
    let ts = parser.parse_line(&line).unwrap();
    assert!(
        ts < now.timestamp(),
        "a future syslog date should roll back a year (ts={ts}, now={})",
        now.timestamp()
    );
}

#[test]
fn syslog_recent_past_not_rolled_back() {
    let parser = DateParser::new(DateFormat::Syslog).unwrap();
    let now = Local::now();
    let past = now - chrono::Duration::days(2);
    let line = format!("{} host sshd: x", past.format("%b %e %H:%M:%S"));
    let ts = parser.parse_line(&line).unwrap();
    // Must be near now (within a few days), not a whole year off.
    assert!(
        (now.timestamp() - ts).abs() < 4 * 86_400,
        "recent past date should not be rolled back a year"
    );
}
