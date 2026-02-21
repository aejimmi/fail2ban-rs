//! Tests for date parsing.

use crate::date::{DateFormat, DateParser};

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
    assert_eq!(ts, 1705312200);
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
