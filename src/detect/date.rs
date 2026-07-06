//! Log line timestamp parsing.
//!
//! Supports four explicit date format presets. No auto-detection — the format
//! must be specified in the jail config. ISO 8601 uses a zero-alloc byte
//! scanner; other formats fall back to regex + chrono.

use chrono::{Datelike, Local, LocalResult, NaiveDateTime, TimeZone};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Supported date format presets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DateFormat {
    /// Syslog: `Jan 15 10:30:00` (no year — assumes current year)
    Syslog,
    /// ISO 8601: `2024-01-15T10:30:00Z` or `2024-01-15T10:30:00+00:00`
    Iso8601,
    /// Unix epoch seconds: `1705312200`
    Epoch,
    /// Common log format: `15/Jan/2024:10:30:00 +0000`
    Common,
}

/// Parser that extracts timestamps from log lines.
pub struct DateParser {
    format: DateFormat,
    /// Regex for syslog/epoch/common formats. Unused for ISO 8601.
    regex: Option<Regex>,
}

impl DateParser {
    /// Create a parser for the given format.
    pub fn new(format: DateFormat) -> Result<Self> {
        // ISO 8601 uses zero-alloc byte scanning — no regex needed.
        let regex = if format == DateFormat::Iso8601 {
            None
        } else {
            let pattern = match format {
                DateFormat::Syslog => r"([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})",
                DateFormat::Epoch => r"(\d{10,})",
                DateFormat::Common => {
                    r"(\d{2})/([A-Z][a-z]{2})/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:\s+([+-]\d{4}))?"
                }
                DateFormat::Iso8601 => unreachable!(),
            };
            Some(Regex::new(pattern).map_err(|e| Error::Regex {
                pattern: pattern.to_string(),
                source: e,
            })?)
        };
        Ok(Self { format, regex })
    }

    /// Parse a log line and extract a unix timestamp.
    pub fn parse_line(&self, line: &str) -> Option<i64> {
        if self.format == DateFormat::Iso8601 {
            scan_iso8601(line.as_bytes())
        } else {
            let caps = self.regex.as_ref()?.captures(line)?;
            match self.format {
                DateFormat::Syslog => parse_syslog(&caps),
                DateFormat::Epoch => parse_epoch(&caps),
                DateFormat::Common => parse_common(&caps),
                DateFormat::Iso8601 => unreachable!(),
            }
        }
    }
}

fn parse_syslog(caps: &regex::Captures<'_>) -> Option<i64> {
    let month_str = caps.get(1)?.as_str();
    let day: u32 = caps.get(2)?.as_str().parse().ok()?;
    let hour: u32 = caps.get(3)?.as_str().parse().ok()?;
    let min: u32 = caps.get(4)?.as_str().parse().ok()?;
    let sec: u32 = caps.get(5)?.as_str().parse().ok()?;
    let month = month_from_abbr(month_str)?;

    // Syslog carries no year — assume the current year, interpreted as LOCAL
    // time (the syslog convention).
    let now = Local::now();
    let ts = syslog_timestamp(now.year(), month, day, hour, min, sec)?;
    // Rollover correction: a December log replayed on January 1st would land
    // ~1 year in the future. If the date is more than a day ahead of now, it
    // belongs to the previous year.
    if ts > now.timestamp() + 86_400 {
        return syslog_timestamp(now.year() - 1, month, day, hour, min, sec);
    }
    Some(ts)
}

/// Build a Unix timestamp for a syslog date, interpreting it as LOCAL time.
///
/// Ambiguous (fall-back DST) or nonexistent (spring-forward DST) local times
/// fall back to a UTC interpretation rather than panicking.
fn syslog_timestamp(year: i32, month: u32, day: u32, hour: u32, min: u32, sec: u32) -> Option<i64> {
    let dt = NaiveDateTime::new(
        chrono::NaiveDate::from_ymd_opt(year, month, day)?,
        chrono::NaiveTime::from_hms_opt(hour, min, sec)?,
    );
    match Local.from_local_datetime(&dt) {
        LocalResult::Single(t) => Some(t.timestamp()),
        // Ambiguous or nonexistent — fall back to UTC interpretation.
        LocalResult::Ambiguous(..) | LocalResult::None => Some(dt.and_utc().timestamp()),
    }
}

fn parse_epoch(caps: &regex::Captures<'_>) -> Option<i64> {
    caps.get(1)?.as_str().parse::<i64>().ok()
}

fn parse_common(caps: &regex::Captures<'_>) -> Option<i64> {
    let day: u32 = caps.get(1)?.as_str().parse().ok()?;
    let month_str = caps.get(2)?.as_str();
    let year: i32 = caps.get(3)?.as_str().parse().ok()?;
    let hour: u32 = caps.get(4)?.as_str().parse().ok()?;
    let min: u32 = caps.get(5)?.as_str().parse().ok()?;
    let sec: u32 = caps.get(6)?.as_str().parse().ok()?;
    let month = month_from_abbr(month_str)?;
    let dt = NaiveDateTime::new(
        chrono::NaiveDate::from_ymd_opt(year, month, day)?,
        chrono::NaiveTime::from_hms_opt(hour, min, sec)?,
    );
    let base = dt.and_utc().timestamp();
    // Apply the captured `+HHMM`/`-HHMM` zone offset if present. The naive
    // fields are local to that offset, so subtract it to reach UTC. Absent an
    // offset the value is treated as UTC (unchanged behavior).
    let offset = caps
        .get(7)
        .and_then(|m| parse_numeric_offset(m.as_str()))
        .unwrap_or(0);
    Some(base - offset)
}

/// Parse a numeric zone offset like `+0500` or `-0300` into seconds.
fn parse_numeric_offset(s: &str) -> Option<i64> {
    let sign = match s.as_bytes().first()? {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    let hh: i64 = s.get(1..3)?.parse().ok()?;
    let mm: i64 = s.get(3..5)?.parse().ok()?;
    Some(sign * (hh * 3600 + mm * 60))
}

// ---------------------------------------------------------------------------
// Fast ISO 8601 parsing — zero allocation, no regex, no chrono.
// ---------------------------------------------------------------------------

/// Scan bytes for an ISO 8601 timestamp (`YYYY-MM-DDThh:mm:ss`).
///
/// Checks position 0 first (the common case), then scans forward.
fn scan_iso8601(b: &[u8]) -> Option<i64> {
    if b.len() < 19 {
        return None;
    }
    for i in 0..=b.len() - 19 {
        let Some(window) = b.get(i..i + 19) else {
            continue;
        };
        // SAFETY of indexing: window is exactly 19 bytes from the .get() above.
        #[allow(clippy::indexing_slicing)]
        let matches_structure = window[4] == b'-'
            && window[7] == b'-'
            && (window[10] == b'T' || window[10] == b' ')
            && window[13] == b':'
            && window[16] == b':';
        if matches_structure {
            let year = parse_4(b, i)?;
            let month = parse_2(b, i + 5)?;
            let day = parse_2(b, i + 8)?;
            let hour = parse_2(b, i + 11)?;
            let min = parse_2(b, i + 14)?;
            let sec = parse_2(b, i + 17)?;
            if (1..=12).contains(&month)
                && (1..=31).contains(&day)
                && hour <= 23
                && min <= 59
                && sec <= 59
            {
                let base = unix_timestamp(year as i32, month, day, hour, min, sec);
                // Apply a trailing zone offset if present; `Z` and naive
                // timestamps (no suffix) are treated as UTC.
                return Some(base - scan_iso_offset(b, i + 19));
            }
        }
    }
    None
}

/// Scan for a timezone offset following the ISO 8601 seconds field.
///
/// Returns the offset in seconds to subtract to reach UTC. `Z`, an absent
/// suffix, and any unrecognized trailer all yield `0` (UTC interpretation).
/// Fractional seconds (`.123`) before the offset are skipped.
fn scan_iso_offset(b: &[u8], mut pos: usize) -> i64 {
    if b.get(pos) == Some(&b'.') {
        pos += 1;
        while matches!(b.get(pos), Some(d) if d.is_ascii_digit()) {
            pos += 1;
        }
    }
    match b.get(pos) {
        Some(b'+') => iso_hm_offset(b, pos + 1, 1),
        Some(b'-') => iso_hm_offset(b, pos + 1, -1),
        _ => 0,
    }
}

/// Parse an `HH:MM` or `HHMM` offset body at `pos`, applying `sign`.
fn iso_hm_offset(b: &[u8], pos: usize, sign: i64) -> i64 {
    let Some(hh) = parse_2(b, pos) else {
        return 0;
    };
    // Minutes may be separated by a colon or run on directly.
    let min_pos = if b.get(pos + 2) == Some(&b':') {
        pos + 3
    } else {
        pos + 2
    };
    let mm = parse_2(b, min_pos).unwrap_or(0);
    sign * (i64::from(hh) * 3600 + i64::from(mm) * 60)
}

/// Parse a 2-digit decimal number from bytes.
#[inline]
fn parse_2(b: &[u8], pos: usize) -> Option<u32> {
    let d1 = (*b.get(pos)?).wrapping_sub(b'0');
    let d2 = (*b.get(pos + 1)?).wrapping_sub(b'0');
    if d1 > 9 || d2 > 9 {
        return None;
    }
    Some(u32::from(d1) * 10 + u32::from(d2))
}

/// Parse a 4-digit decimal number from bytes.
#[inline]
fn parse_4(b: &[u8], pos: usize) -> Option<u32> {
    let d1 = (*b.get(pos)?).wrapping_sub(b'0');
    let d2 = (*b.get(pos + 1)?).wrapping_sub(b'0');
    let d3 = (*b.get(pos + 2)?).wrapping_sub(b'0');
    let d4 = (*b.get(pos + 3)?).wrapping_sub(b'0');
    if d1 > 9 || d2 > 9 || d3 > 9 || d4 > 9 {
        return None;
    }
    Some(u32::from(d1) * 1000 + u32::from(d2) * 100 + u32::from(d3) * 10 + u32::from(d4))
}

/// Convert date/time components to Unix timestamp (UTC).
///
/// Uses Howard Hinnant's `civil_from_days` algorithm — pure arithmetic,
/// no branches, no loops, no allocations.
fn unix_timestamp(year: i32, month: u32, day: u32, hour: u32, min: u32, sec: u32) -> i64 {
    let y = if month <= 2 {
        i64::from(year) - 1
    } else {
        i64::from(year)
    };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let m = if month > 2 {
        u64::from(month) - 3
    } else {
        u64::from(month) + 9
    };
    let doy = (153 * m + 2) / 5 + u64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe as i64 - 719_468;
    days * 86400 + i64::from(hour) * 3600 + i64::from(min) * 60 + i64::from(sec)
}

fn month_from_abbr(s: &str) -> Option<u32> {
    match s {
        "Jan" => Some(1),
        "Feb" => Some(2),
        "Mar" => Some(3),
        "Apr" => Some(4),
        "May" => Some(5),
        "Jun" => Some(6),
        "Jul" => Some(7),
        "Aug" => Some(8),
        "Sep" => Some(9),
        "Oct" => Some(10),
        "Nov" => Some(11),
        "Dec" => Some(12),
        _ => None,
    }
}

#[cfg(test)]
#[path = "date_test.rs"]
mod date_test;
