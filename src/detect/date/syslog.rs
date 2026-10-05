//! Syslog timestamp parsing (`Mmm dd hh:mm:ss`, no year, local time).
//!
//! Two parts, both replacing per-line work that used to dominate the cost:
//!
//! - **Scanner.** A byte scanner with the exact semantics of the former regex
//!   `([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})` (unanchored,
//!   leftmost match, no retry after a leftmost match fails validation). The
//!   regex runs in Unicode mode, where `\s` and `\d` also match non-ASCII
//!   whitespace and digits. Whenever the scanner reaches a non-ASCII byte at a
//!   position where `\s` or `\d` is being tested, it defers to that regex, so
//!   the accepted set of lines is unchanged.
//! - **Conversion cache.** The current year and the local UTC offset of one
//!   local wall-clock hour are cached in atomics; see [`SyslogCache`].

use std::sync::atomic::{AtomicI32, AtomicI64, AtomicU64, Ordering};

use chrono::{DateTime, Datelike, LocalResult, NaiveDateTime, Offset, TimeZone, Utc};
use regex::Regex;

use super::unix_timestamp;

/// Seconds in a day; also a strict bound on any UTC offset chrono can express.
const DAY: i64 = 86_400;

/// Raw syslog timestamp fields. Numeric fields are not range-checked yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SyslogFields {
    month: [u8; 3],
    day: u32,
    hour: u32,
    min: u32,
    sec: u32,
}

/// Outcome of scanning a line for a syslog timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scan {
    /// Leftmost structural match.
    Found(SyslogFields),
    /// No position matches.
    Absent,
    /// A non-ASCII byte made the outcome depend on Unicode classes.
    NeedsRegex,
}

/// Why a match attempt at one position stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Miss {
    /// The pattern definitely does not match at this position.
    NoMatch,
    /// Unicode `\s`/`\d` could match here; only the regex can decide.
    NonAscii,
}

/// Parse a syslog timestamp from `line`.
///
/// `regex` is the Unicode-mode fallback used only when [`Scan::NeedsRegex`].
pub(super) fn parse(line: &str, regex: Option<&Regex>, cache: &SyslogCache) -> Option<i64> {
    let fields = match scan(line.as_bytes()) {
        Scan::Found(f) => f,
        Scan::Absent => return None,
        Scan::NeedsRegex => fields_from_regex(&regex?.captures(line)?)?,
    };
    cache.resolve(&chrono::Local, &fields)
}

/// Extract fields from regex captures (Unicode fallback path).
fn fields_from_regex(caps: &regex::Captures<'_>) -> Option<SyslogFields> {
    Some(SyslogFields {
        month: caps.get(1)?.as_str().as_bytes().try_into().ok()?,
        day: caps.get(2)?.as_str().parse().ok()?,
        hour: caps.get(3)?.as_str().parse().ok()?,
        min: caps.get(4)?.as_str().parse().ok()?,
        sec: caps.get(5)?.as_str().parse().ok()?,
    })
}

/// Find the leftmost syslog timestamp in `b`.
fn scan(b: &[u8]) -> Scan {
    for i in 0..b.len() {
        match match_at(b, i) {
            Ok(f) => return Scan::Found(f),
            Err(Miss::NoMatch) => {}
            Err(Miss::NonAscii) => return Scan::NeedsRegex,
        }
    }
    Scan::Absent
}

/// Try to match the pattern starting exactly at byte `i`.
fn match_at(b: &[u8], i: usize) -> Result<SyslogFields, Miss> {
    let Some(&[m0, m1, m2]) = b.get(i..i + 3) else {
        return Err(Miss::NoMatch);
    };
    if !(m0.is_ascii_uppercase() && m1.is_ascii_lowercase() && m2.is_ascii_lowercase()) {
        return Err(Miss::NoMatch);
    }
    let pos = space_run(b, i + 3)?;
    let (day, pos) = day_field(b, pos)?;
    let pos = space_run(b, pos)?;
    let (hour, min, sec) = time_field(b, pos)?;
    Ok(SyslogFields {
        month: [m0, m1, m2],
        day,
        hour,
        min,
        sec,
    })
}

/// ASCII members of Unicode `White_Space` (what regex `\s` matches in ASCII).
fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0B | 0x0C | b'\r')
}

/// Match `\s+` at `pos`; returns the position after the run.
fn space_run(b: &[u8], pos: usize) -> Result<usize, Miss> {
    let mut p = pos;
    while let Some(&c) = b.get(p) {
        if is_space(c) {
            p += 1;
        } else if !c.is_ascii() {
            return Err(Miss::NonAscii);
        } else {
            break;
        }
    }
    if p == pos { Err(Miss::NoMatch) } else { Ok(p) }
}

/// Match one `\d` at `pos`.
fn digit(b: &[u8], pos: usize) -> Result<u32, Miss> {
    match b.get(pos) {
        Some(&c) if c.is_ascii_digit() => Ok(u32::from(c - b'0')),
        Some(&c) if !c.is_ascii() => Err(Miss::NonAscii),
        _ => Err(Miss::NoMatch),
    }
}

/// Match `\d{1,2}` at `pos` (greedy; the following `\s+` is checked later).
fn day_field(b: &[u8], pos: usize) -> Result<(u32, usize), Miss> {
    let d1 = digit(b, pos)?;
    match digit(b, pos + 1) {
        Ok(d2) => Ok((d1 * 10 + d2, pos + 2)),
        Err(Miss::NonAscii) => Err(Miss::NonAscii),
        Err(Miss::NoMatch) => Ok((d1, pos + 1)),
    }
}

/// Match `\d{2}:\d{2}:\d{2}` at `pos`.
fn time_field(b: &[u8], pos: usize) -> Result<(u32, u32, u32), Miss> {
    let two = |p: usize| -> Result<u32, Miss> { Ok(digit(b, p)? * 10 + digit(b, p + 1)?) };
    let colon = |p: usize| -> Result<(), Miss> {
        if b.get(p) == Some(&b':') {
            Ok(())
        } else {
            Err(Miss::NoMatch)
        }
    };
    let hour = two(pos)?;
    colon(pos + 2)?;
    let min = two(pos + 3)?;
    colon(pos + 5)?;
    let sec = two(pos + 6)?;
    Ok((hour, min, sec))
}

fn month_from_bytes(m: [u8; 3]) -> Option<u32> {
    let n = match &m {
        b"Jan" => 1,
        b"Feb" => 2,
        b"Mar" => 3,
        b"Apr" => 4,
        b"May" => 5,
        b"Jun" => 6,
        b"Jul" => 7,
        b"Aug" => 8,
        b"Sep" => 9,
        b"Oct" => 10,
        b"Nov" => 11,
        b"Dec" => 12,
        _ => return None,
    };
    Some(n)
}

fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Seconds since the epoch of local wall-clock time `year-month-day f.time`,
/// read as if it were UTC; `None` where chrono would reject the date or time.
fn naive_seconds(year: i32, month: u32, f: &SyslogFields) -> Option<i64> {
    let valid = (1..=days_in_month(year, month)).contains(&f.day)
        && f.hour < 24
        && f.min < 60
        && f.sec < 60;
    valid.then(|| unix_timestamp(year, month, f.day, f.hour, f.min, f.sec))
}

/// Lock-free cache for syslog local-time conversion.
///
/// * **Year.** The local year of "now". Every chrono offset is strictly
///   within ±1 day, so for `now` in `[Jan 1 Y + 1 day, Jan 1 Y+1 - 1 day)`
///   (UTC) the local year is `Y` in *any* zone. The cached year is used only
///   inside that window; within a day of New Year it is recomputed from chrono
///   on every call.
/// * **Offset.** The offset of one local wall-clock hour `[H:00:00,
///   H:59:59]`. It is stored only when chrono maps both endpoints of the hour
///   to a single (unambiguous) time with the same offset, i.e. no DST
///   transition, gap or overlap begins inside the hour (this assumes no zone
///   has two transitions within one hour that cancel out). Hours containing a
///   transition are never cached and always go through chrono, so the
///   ambiguous/nonexistent → UTC fallback is unchanged. The entry is only
///   trusted during the wall-clock second it was verified in, so a system
///   timezone change is picked up as quickly as chrono itself notices it.
#[derive(Debug, Default)]
pub(super) struct SyslogCache {
    /// Cached local year, `0` when empty.
    year: AtomicI32,
    /// `(hour_index + 1) << 32 | offset_seconds as u32`, `0` when empty.
    entry: AtomicU64,
    /// Unix second in which `entry` was last verified against chrono.
    verified_at: AtomicI64,
}

impl SyslogCache {
    /// Resolve fields to a Unix timestamp at the current time in `tz`.
    pub(super) fn resolve<Tz: TimeZone>(&self, tz: &Tz, f: &SyslogFields) -> Option<i64> {
        let now = Utc::now().timestamp();
        let year = self.year_at(tz, now)?;
        self.resolve_at(tz, f, now, year)
    }

    /// Resolve fields given `now` (Unix seconds) and its local `year`.
    ///
    /// Syslog has no year: use the current one, and if that puts the date
    /// more than a day ahead of now (a December line read in January), use the
    /// previous year instead.
    fn resolve_at<Tz: TimeZone>(
        &self,
        tz: &Tz,
        f: &SyslogFields,
        now: i64,
        year: i32,
    ) -> Option<i64> {
        let month = month_from_bytes(f.month)?;
        let naive = naive_seconds(year, month, f)?;
        // |offset| < DAY, so the local result lies in (naive - DAY, naive + DAY).
        // Skip the exact conversion when the rollover decision is already
        // certain; the result is identical and avoids churning the cache.
        if naive - DAY <= now + DAY {
            let ts = self.to_utc(tz, naive, now)?;
            if ts <= now + DAY {
                return Some(ts);
            }
        }
        let prev = naive_seconds(year - 1, month, f)?;
        self.to_utc(tz, prev, now)
    }

    /// Local year at Unix second `now`, cached when provably stable.
    fn year_at<Tz: TimeZone>(&self, tz: &Tz, now: i64) -> Option<i32> {
        let cached = self.year.load(Ordering::Relaxed);
        if cached != 0 && year_is_certain(cached, now) {
            return Some(cached);
        }
        let year = tz.timestamp_opt(now, 0).single()?.year();
        if year_is_certain(year, now) {
            self.year.store(year, Ordering::Relaxed);
        }
        Some(year)
    }

    /// Convert local wall-clock seconds to UTC, preserving the chrono
    /// semantics: ambiguous or nonexistent local times are read as UTC.
    fn to_utc<Tz: TimeZone>(&self, tz: &Tz, naive: i64, now: i64) -> Option<i64> {
        let hour = naive.div_euclid(3600);
        if let Some(off) = self.cached_offset(hour, now) {
            return Some(naive - off);
        }
        if let Some(off) = self.verify_hour(tz, hour, now) {
            return Some(naive - off);
        }
        let dt = naive_datetime(naive)?;
        Some(match single_offset(tz, &dt) {
            Some(off) => naive - off,
            None => naive,
        })
    }

    fn cached_offset(&self, hour: i64, now: i64) -> Option<i64> {
        let key = hour_key(hour)?;
        if self.verified_at.load(Ordering::Acquire) != now {
            return None;
        }
        let entry = self.entry.load(Ordering::Relaxed);
        // Truncating casts unpack the two halves stored by `verify_hour`.
        let off = entry as u32 as i32;
        ((entry >> 32) as u32 == key).then_some(i64::from(off))
    }

    /// Check whether `hour` has one constant, unambiguous offset; if so cache
    /// and return it.
    fn verify_hour<Tz: TimeZone>(&self, tz: &Tz, hour: i64, now: i64) -> Option<i64> {
        let key = hour_key(hour)?;
        let start = hour * 3600;
        let first = single_offset(tz, &naive_datetime(start)?)?;
        let last = single_offset(tz, &naive_datetime(start + 3599)?)?;
        if first != last {
            return None;
        }
        let off = i32::try_from(first).ok()?;
        self.entry.store(
            (u64::from(key) << 32) | u64::from(off as u32),
            Ordering::Relaxed,
        );
        self.verified_at.store(now, Ordering::Release);
        Some(first)
    }
}

/// True when the local year at Unix second `now` must be `year` in any zone.
fn year_is_certain(year: i32, now: i64) -> bool {
    let start = unix_timestamp(year, 1, 1, 0, 0, 0);
    let end = unix_timestamp(year + 1, 1, 1, 0, 0, 0);
    now >= start + DAY && now < end - DAY
}

/// Cache key for a local hour index; `None` if it cannot be packed.
fn hour_key(hour: i64) -> Option<u32> {
    u32::try_from(hour.checked_add(1)?).ok().filter(|&k| k != 0)
}

fn naive_datetime(secs: i64) -> Option<NaiveDateTime> {
    DateTime::from_timestamp(secs, 0).map(|d| d.naive_utc())
}

/// Offset (seconds east of UTC) if `local` maps to exactly one instant.
fn single_offset<Tz: TimeZone>(tz: &Tz, local: &NaiveDateTime) -> Option<i64> {
    match tz.offset_from_local_datetime(local) {
        LocalResult::Single(o) => Some(i64::from(o.fix().local_minus_utc())),
        LocalResult::Ambiguous(..) | LocalResult::None => None,
    }
}

#[cfg(test)]
#[path = "syslog_test.rs"]
mod syslog_test;

#[cfg(test)]
#[path = "syslog_pin_test.rs"]
mod syslog_pin_test;
