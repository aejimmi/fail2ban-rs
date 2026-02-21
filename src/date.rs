//! Log line timestamp parsing.
//!
//! Supports four explicit date format presets. No auto-detection — the format
//! must be specified in the jail config.

use chrono::{NaiveDateTime, Utc};
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
    regex: Regex,
}

impl DateParser {
    /// Create a parser for the given format.
    pub fn new(format: DateFormat) -> Result<Self> {
        let pattern = match format {
            DateFormat::Syslog => r"([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})",
            DateFormat::Iso8601 => r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})",
            DateFormat::Epoch => r"(\d{10,})",
            DateFormat::Common => r"(\d{2})/([A-Z][a-z]{2})/(\d{4}):(\d{2}):(\d{2}):(\d{2})",
        };
        let regex = Regex::new(pattern).map_err(|e| Error::Regex {
            pattern: pattern.to_string(),
            source: e,
        })?;
        Ok(Self { format, regex })
    }

    /// Parse a log line and extract a unix timestamp.
    pub fn parse_line(&self, line: &str) -> Option<i64> {
        let caps = self.regex.captures(line)?;
        match self.format {
            DateFormat::Syslog => self.parse_syslog(&caps),
            DateFormat::Iso8601 => self.parse_iso8601(&caps),
            DateFormat::Epoch => self.parse_epoch(&caps),
            DateFormat::Common => self.parse_common(&caps),
        }
    }

    fn parse_syslog(&self, caps: &regex::Captures<'_>) -> Option<i64> {
        let month_str = caps.get(1)?.as_str();
        let day: u32 = caps.get(2)?.as_str().parse().ok()?;
        let hour: u32 = caps.get(3)?.as_str().parse().ok()?;
        let min: u32 = caps.get(4)?.as_str().parse().ok()?;
        let sec: u32 = caps.get(5)?.as_str().parse().ok()?;
        let month = month_from_abbr(month_str)?;
        let year = Utc::now().format("%Y").to_string().parse::<i32>().ok()?;
        let dt = NaiveDateTime::new(
            chrono::NaiveDate::from_ymd_opt(year, month, day)?,
            chrono::NaiveTime::from_hms_opt(hour, min, sec)?,
        );
        Some(dt.and_utc().timestamp())
    }

    fn parse_iso8601(&self, caps: &regex::Captures<'_>) -> Option<i64> {
        let date_str = caps.get(1)?.as_str();
        let time_str = caps.get(2)?.as_str();
        let combined = format!("{date_str}T{time_str}");
        let dt = NaiveDateTime::parse_from_str(&combined, "%Y-%m-%dT%H:%M:%S").ok()?;
        Some(dt.and_utc().timestamp())
    }

    fn parse_epoch(&self, caps: &regex::Captures<'_>) -> Option<i64> {
        caps.get(1)?.as_str().parse::<i64>().ok()
    }

    fn parse_common(&self, caps: &regex::Captures<'_>) -> Option<i64> {
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
        Some(dt.and_utc().timestamp())
    }
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
