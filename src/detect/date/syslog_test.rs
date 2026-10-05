//! Differential tests: the byte scanner + cache against a verbatim copy of the
//! previous regex + chrono implementation (the oracle).

use super::*;

use std::sync::LazyLock;

use chrono::{FixedOffset, Local, NaiveDate};

use crate::detect::date::{DateFormat, DateParser};

// ---------------------------------------------------------------------------
// Oracle: the pre-optimization implementation, copied verbatim (Local, now).
// ---------------------------------------------------------------------------

const OLD_PATTERN: &str = r"([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})";

static OLD_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(OLD_PATTERN).expect("oracle regex compiles"));

fn old_parse_line(line: &str) -> Option<i64> {
    let caps = OLD_RE.captures(line)?;
    old_parse_syslog(&caps)
}

fn old_parse_syslog(caps: &regex::Captures<'_>) -> Option<i64> {
    let month_str = caps.get(1)?.as_str();
    let day: u32 = caps.get(2)?.as_str().parse().ok()?;
    let hour: u32 = caps.get(3)?.as_str().parse().ok()?;
    let min: u32 = caps.get(4)?.as_str().parse().ok()?;
    let sec: u32 = caps.get(5)?.as_str().parse().ok()?;
    let month = super::super::month_from_abbr(month_str)?;
    let now = Local::now();
    let ts = old_syslog_timestamp(&Local, now.year(), month, day, hour, min, sec)?;
    if ts > now.timestamp() + 86_400 {
        return old_syslog_timestamp(&Local, now.year() - 1, month, day, hour, min, sec);
    }
    Some(ts)
}

/// Verbatim except that the zone is a parameter (the original used `Local`).
fn old_syslog_timestamp<Tz: TimeZone>(
    tz: &Tz,
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    min: u32,
    sec: u32,
) -> Option<i64> {
    let dt = NaiveDateTime::new(
        chrono::NaiveDate::from_ymd_opt(year, month, day)?,
        chrono::NaiveTime::from_hms_opt(hour, min, sec)?,
    );
    match tz.from_local_datetime(&dt) {
        LocalResult::Single(t) => Some(t.timestamp()),
        LocalResult::Ambiguous(..) | LocalResult::None => Some(dt.and_utc().timestamp()),
    }
}

/// The oracle with an injected zone and "now" (same logic as `old_parse_syslog`).
pub(super) fn old_parse_at<Tz: TimeZone>(tz: &Tz, now: i64, line: &str) -> Option<i64> {
    let caps = OLD_RE.captures(line)?;
    let p = |i: usize| caps.get(i).and_then(|m| m.as_str().parse::<u32>().ok());
    let (day, hour, min, sec) = (p(2)?, p(3)?, p(4)?, p(5)?);
    let month = super::super::month_from_abbr(caps.get(1)?.as_str())?;
    let year = tz.timestamp_opt(now, 0).single()?.year();
    let ts = old_syslog_timestamp(tz, year, month, day, hour, min, sec)?;
    if ts > now + 86_400 {
        return old_syslog_timestamp(tz, year - 1, month, day, hour, min, sec);
    }
    Some(ts)
}

/// New implementation with an injected zone and "now".
pub(super) fn new_parse_at<Tz: TimeZone>(
    cache: &SyslogCache,
    tz: &Tz,
    now: i64,
    line: &str,
) -> Option<i64> {
    let fields = match scan(line.as_bytes()) {
        Scan::Found(f) => f,
        Scan::Absent => return None,
        Scan::NeedsRegex => fields_from_regex(&OLD_RE.captures(line)?)?,
    };
    let year = cache.year_at(tz, now)?;
    cache.resolve_at(tz, &fields, now, year)
}

// ---------------------------------------------------------------------------
// Synthetic DST zones (deterministic regardless of the host timezone).
// ---------------------------------------------------------------------------

/// Zone defined by an initial offset and `(utc_instant, new_offset)` steps.
#[derive(Debug)]
pub(super) struct Spec {
    initial: i32,
    steps: Vec<(i64, i32)>,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct TestZone(pub(super) &'static Spec);

#[derive(Debug, Clone, Copy)]
pub(super) struct TestOffset {
    zone: TestZone,
    secs: i32,
}

impl Offset for TestOffset {
    fn fix(&self) -> FixedOffset {
        FixedOffset::east_opt(self.secs).expect("test offsets are within a day")
    }
}

impl TestZone {
    fn offset(self, secs: i32) -> TestOffset {
        TestOffset { zone: self, secs }
    }

    fn at_utc(self, t: i64) -> TestOffset {
        let secs = self.0.steps.iter().rfind(|s| t >= s.0);
        self.offset(secs.map_or(self.0.initial, |s| s.1))
    }

    fn at_local(self, local: i64) -> LocalResult<TestOffset> {
        let mut hits = Vec::new();
        let (mut start, mut off) = (i64::MIN, self.0.initial);
        for &(at, next) in self.0.steps.iter().chain([(i64::MAX, 0)].iter()) {
            let utc = local - i64::from(off);
            if utc >= start && utc < at {
                hits.push(off);
            }
            (start, off) = (at, next);
        }
        match hits[..] {
            [o] => LocalResult::Single(self.offset(o)),
            [a, b] => LocalResult::Ambiguous(self.offset(a), self.offset(b)),
            _ => LocalResult::None,
        }
    }
}

impl TimeZone for TestZone {
    type Offset = TestOffset;

    fn from_offset(offset: &TestOffset) -> Self {
        offset.zone
    }

    fn offset_from_local_date(&self, local: &NaiveDate) -> LocalResult<TestOffset> {
        self.offset_from_local_datetime(&local.and_time(chrono::NaiveTime::MIN))
    }

    fn offset_from_local_datetime(&self, local: &NaiveDateTime) -> LocalResult<TestOffset> {
        self.at_local(local.and_utc().timestamp())
    }

    fn offset_from_utc_date(&self, utc: &NaiveDate) -> TestOffset {
        self.offset_from_utc_datetime(&utc.and_time(chrono::NaiveTime::MIN))
    }

    fn offset_from_utc_datetime(&self, utc: &NaiveDateTime) -> TestOffset {
        self.at_utc(utc.and_utc().timestamp())
    }
}

/// Unix timestamp of a UTC wall-clock instant.
pub(super) fn utc(y: i32, mo: u32, d: u32, h: u32, mi: u32, s: u32) -> i64 {
    unix_timestamp(y, mo, d, h, mi, s)
}

/// US Eastern for 2025-2026: EST -5h, EDT -4h, transitions at 02:00 local.
pub(super) static EASTERN: LazyLock<Spec> = LazyLock::new(|| Spec {
    initial: -18_000,
    steps: vec![
        (utc(2025, 3, 9, 7, 0, 0), -14_400),
        (utc(2025, 11, 2, 6, 0, 0), -18_000),
        (utc(2026, 3, 8, 7, 0, 0), -14_400),
        (utc(2026, 11, 1, 6, 0, 0), -18_000),
    ],
});

/// Chatham-like: +12:45 / +13:45, transitions at 02:45 local standard time,
/// i.e. NOT aligned to the hour.
pub(super) static CHATHAM: LazyLock<Spec> = LazyLock::new(|| Spec {
    initial: 49_500,
    steps: vec![
        (utc(2025, 4, 5, 14, 0, 0), 45_900),
        (utc(2025, 9, 27, 14, 0, 0), 49_500),
        (utc(2026, 4, 4, 14, 0, 0), 45_900),
        (utc(2026, 9, 26, 14, 0, 0), 49_500),
    ],
});

/// A 15-minute shift strictly inside an hour: gap [02:15, 02:30) on May 10,
/// overlap [02:15, 02:30) on Oct 11 (2026). Both endpoints of local hour 02
/// are unambiguous but have different offsets.
pub(super) static QUARTER: LazyLock<Spec> = LazyLock::new(|| Spec {
    initial: 3_600,
    steps: vec![
        (utc(2026, 5, 10, 1, 15, 0), 4_500),
        (utc(2026, 10, 11, 1, 15, 0), 3_600),
    ],
});

// ---------------------------------------------------------------------------
// Line generators.
// ---------------------------------------------------------------------------

const MONTHS: [&str; 15] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec", "Xyz",
    "JAN", "jan",
];

/// Day renderings: space-padded, zero-padded, bare, plus odd separators.
fn day_variants(day: u32) -> [String; 4] {
    [
        format!("{day:>2} "),
        format!("{day:02} "),
        format!("{day}\t"),
        format!("{day}   "),
    ]
}

/// Every minute (seconds 0 and 59) of each local calendar day in `days`.
fn minute_lines(days: &[(u32, u32)]) -> Vec<String> {
    let mut out = Vec::new();
    for &(mo, d) in days {
        let month = MONTHS.get(mo as usize - 1).expect("month 1-12");
        for m in 0..1440 {
            for s in [0, 59] {
                out.push(format!(
                    "{month} {d:>2} {:02}:{:02}:{s:02} h",
                    m / 60,
                    m % 60
                ));
            }
        }
    }
    out
}

/// Compare old and new on the host `Local` zone, tolerating a clock tick
/// between the oracle calls (the result must equal one of them).
fn assert_matches_oracle(parser: &DateParser, line: &str) {
    let before = old_parse_line(line);
    let got = parser.parse_line(line);
    let after = old_parse_line(line);
    assert!(
        got == before || got == after,
        "line {line:?}: new={got:?} old={before:?}/{after:?}"
    );
}

fn syslog_parser() -> DateParser {
    DateParser::new(DateFormat::Syslog).expect("syslog parser")
}

// ---------------------------------------------------------------------------
// Host-timezone differential tests (via the public DateParser).
// ---------------------------------------------------------------------------

#[test]
fn test_syslog_differential_generated_grid() {
    let parser = syslog_parser();
    let times = [
        "00:00:00", "01:30:59", "02:00:00", "02:30:00", "03:00:00", "12:00:00", "23:59:59",
        "24:00:00", "23:60:00", "23:59:60", "99:99:99", "1:00:00", "10:0:00",
    ];
    let prefixes = ["", "<13>", "host: ", "xJan ", "Jan 123 "];
    for month in MONTHS {
        for day in 0..=32 {
            for d in day_variants(day) {
                for t in times {
                    for p in prefixes {
                        assert_matches_oracle(&parser, &format!("{p}{month} {d}{t} sshd: x"));
                    }
                }
            }
        }
    }
}

#[test]
fn test_syslog_differential_byte_substitution() {
    let parser = syslog_parser();
    // The trailing timestamp catches scans that wrongly skip past a
    // leftmost match the regex would have taken (and then rejected).
    let template = "Jan  5 10:30:00 host Feb  1 11:00:00";
    let mut fillers: Vec<String> = (0u8..128).map(|b| char::from(b).to_string()).collect();
    for c in [
        '\u{a0}', '\u{85}', '\u{2003}', '\u{3000}', '\u{663}', '\u{ff13}', 'é',
    ] {
        fillers.push(c.to_string());
    }
    for pos in 0..16 {
        let (head, tail) = template.split_at(pos);
        for f in &fillers {
            assert_matches_oracle(&parser, &format!("{head}{f}{}", &tail[1..]));
            assert_matches_oracle(&parser, &format!("{head}{f}{tail}"));
        }
    }
}

#[test]
fn test_syslog_differential_truncated_and_embedded() {
    let parser = syslog_parser();
    let full = "Dec 10 06:55:46 LabSZ sshd[24200]: Failed password from 1.2.3.4";
    for end in 0..=full.len() {
        assert_matches_oracle(&parser, &full[..end]);
        assert_matches_oracle(&parser, &format!("prefix Oct  5 {}", &full[..end]));
    }
    for line in [
        "",
        "no timestamp here",
        "Ab 1 10:00:00",
        "Xyz 15 10:30:00 then Jan 15 10:30:00",
        "Jan 123 10:30:00 then Feb  1 10:00:00",
        "Jan 5 10:30:00",
        "jJan  5 10:30:00",
        "Jan\u{a0}5 10:30:00",
        "Jan \u{663} 10:30:00 then Feb  1 10:00:00",
        "Jan 1\u{663} 10:30:00 then Feb  1 10:00:00",
        "Jan  5 1\u{663}:30:00 then Feb  1 10:00:00",
        "Jan  5 10:30:0\u{ff13} then Feb  1 10:00:00",
        "Jos\u{e9} Jan  5 10:30:00",
        "Feb 29 12:00:00",
        "Feb 30 12:00:00",
        "Apr 31 12:00:00",
        "Jan 00 12:00:00",
    ] {
        assert_matches_oracle(&parser, line);
    }
}

/// Local calendar days in `year` whose offsets are not constant.
fn host_transition_days(year: i32) -> Vec<(u32, u32)> {
    let mut days = Vec::new();
    let mut day = NaiveDate::from_ymd_opt(year, 1, 1).expect("valid date");
    while day.year() == year {
        let offs: Vec<_> = (0..24)
            .map(|h| single_offset(&Local, &day.and_hms_opt(h, 0, 0).expect("valid time")))
            .collect();
        if offs.iter().any(|o| Some(o) != offs.first() || o.is_none()) {
            days.push((day.month(), day.day()));
        }
        day = day.succ_opt().expect("next day");
    }
    days
}

#[test]
fn test_syslog_differential_host_year_and_dst_days() {
    let parser = syslog_parser();
    let year = Local::now().year();
    for y in [year, year - 1] {
        for line in minute_lines(&host_transition_days(y)) {
            assert_matches_oracle(&parser, &line);
        }
    }
    // Hourly sweep over a whole year (year is inferred, so this covers both
    // the current-year and the rolled-back paths).
    let mut day = NaiveDate::from_ymd_opt(2024, 1, 1).expect("valid date");
    while day.year() == 2024 {
        let month = MONTHS.get(day.month0() as usize).expect("month");
        for h in 0..24 {
            let line = format!("{month} {:>2} {h:02}:30:15 x", day.day());
            assert_matches_oracle(&parser, &line);
        }
        day = day.succ_opt().expect("next day");
    }
}

// ---------------------------------------------------------------------------
// Synthetic-zone differential tests (deterministic DST coverage).
// ---------------------------------------------------------------------------

fn transition_days(spec: &Spec) -> Vec<(u32, u32)> {
    let mut days: Vec<(u32, u32)> = Vec::new();
    for &(at, _) in &spec.steps {
        for delta in [-DAY, 0, DAY] {
            let d = DateTime::from_timestamp(at + delta, 0).expect("in range");
            days.push((d.month(), d.day()));
        }
    }
    days.sort_unstable();
    days.dedup();
    days
}

fn run_zone_differential(spec: &'static Spec) {
    let tz = TestZone(spec);
    let lines = minute_lines(&transition_days(spec));
    let nows = [
        utc(2026, 12, 31, 12, 0, 0),
        utc(2026, 6, 15, 12, 0, 0),
        utc(2026, 3, 8, 6, 59, 30),
        utc(2026, 9, 26, 13, 0, 0),
        utc(2027, 1, 1, 3, 0, 0),
    ];
    for now in nows {
        let cache = SyslogCache::default();
        for line in lines.iter().chain(lines.iter().rev()) {
            let want = old_parse_at(&tz, now, line);
            let got = new_parse_at(&cache, &tz, now, line);
            assert_eq!(got, want, "now={now} line={line:?}");
        }
    }
}

#[test]
fn test_syslog_differential_synthetic_us_eastern() {
    run_zone_differential(&EASTERN);
}

#[test]
fn test_syslog_differential_synthetic_non_hour_aligned() {
    run_zone_differential(&CHATHAM);
}

#[test]
fn test_syslog_differential_synthetic_quarter_hour_shift() {
    run_zone_differential(&QUARTER);
}

#[test]
fn test_syslog_differential_year_window_extreme_offsets() {
    for secs in [-86_399, -43_200, -1, 0, 1, 50_400, 86_399] {
        let tz = FixedOffset::east_opt(secs).expect("offset in range");
        let cache = SyslogCache::default();
        // Seed the year cache mid-year, then sweep New Year minute by minute.
        assert_eq!(cache.year_at(&tz, utc(2026, 7, 1, 0, 0, 0)), Some(2026));
        let new_year = utc(2027, 1, 1, 0, 0, 0);
        for t in (new_year - 3 * DAY..new_year + 3 * DAY).step_by(60) {
            let want = tz.timestamp_opt(t, 0).single().map(|d| d.year());
            assert_eq!(cache.year_at(&tz, t), want, "offset={secs} t={t}");
            let line = "Dec 31 23:59:59 x";
            assert_eq!(
                new_parse_at(&cache, &tz, t, line),
                old_parse_at(&tz, t, line)
            );
        }
    }
}
