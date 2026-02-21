//! Human-friendly duration parsing for configuration values.
//!
//! Accepts both raw integers (seconds) and duration strings like
//! `"10m"`, `"1h"`, `"1d"`, `"1w"`.

use crate::error::{Error, Result};

/// Parse a duration string into seconds.
///
/// Supported suffixes: `s` (seconds), `m` (minutes), `h` (hours),
/// `d` (days), `w` (weeks). Plain integers are treated as seconds.
pub fn parse_duration(s: &str) -> Result<i64> {
    let s = s.trim();
    if s.is_empty() {
        return Err(Error::config("empty duration string"));
    }

    // Try plain integer first.
    if let Ok(n) = s.parse::<i64>() {
        return Ok(n);
    }

    let (digits, suffix) = s.split_at(s.len() - 1);
    let value: i64 = digits
        .trim()
        .parse()
        .map_err(|_| Error::config(format!("invalid duration: {s}")))?;

    let multiplier: i64 = match suffix {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        "w" => 604800,
        _ => return Err(Error::config(format!("unknown duration suffix: {suffix}"))),
    };

    Ok(value * multiplier)
}

/// Serde deserializer that accepts both integers and duration strings.
pub fn deserialize_duration<'de, D>(deserializer: D) -> std::result::Result<i64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;

    struct DurationVisitor;

    impl<'de> de::Visitor<'de> for DurationVisitor {
        type Value = i64;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("an integer (seconds) or a duration string like \"10m\", \"1h\"")
        }

        fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<i64, E> {
            Ok(v)
        }

        fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<i64, E> {
            i64::try_from(v).map_err(|_| E::custom("duration too large"))
        }

        fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<i64, E> {
            parse_duration(v).map_err(|e| E::custom(e.to_string()))
        }
    }

    deserializer.deserialize_any(DurationVisitor)
}
