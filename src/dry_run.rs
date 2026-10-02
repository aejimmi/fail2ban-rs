//! Dry-run analysis — replay a log file through jail matchers without banning.
//!
//! The log is streamed once with every selected jail's matcher active per
//! line. Per-IP state is bounded: a failure count, a ring of the last
//! `max_retry` timestamps, and a sticky would-ban flag. Memory therefore grows
//! with the number of unique offending IPs, never with log size.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::IpAddr;
use std::path::Path;

use anyhow::{Context, Result};

use fail2ban_rs::config::{Config, JailConfig};
use fail2ban_rs::detect::date::DateParser;
use fail2ban_rs::detect::ignore::IgnoreList;
use fail2ban_rs::detect::matcher::JailMatcher;
use fail2ban_rs::text::lossy;
use fail2ban_rs::track::circular::CircularTimestamps;

/// Bounded per-IP failure state for one jail.
pub(crate) struct IpState {
    /// Total matched failures for this IP.
    pub(crate) count: usize,
    /// The most recent `max_retry` failure timestamps.
    ring: CircularTimestamps,
    /// Whether `max_retry` failures ever fell within one `find_time` window.
    pub(crate) would_ban: bool,
}

impl IpState {
    /// Create empty state sized for `max_retry` failures.
    pub(crate) fn new(max_retry: u32) -> Self {
        Self {
            count: 0,
            ring: CircularTimestamps::new(max_retry as usize),
            would_ban: false,
        }
    }

    /// Record one failure. Mirrors daemon semantics: `max_retry` failures
    /// must fall within a `find_time`-second window. Once the threshold is
    /// reached the IP stays flagged, so the ring no longer needs updating.
    pub(crate) fn record(&mut self, ts: i64, find_time: i64) {
        self.count += 1;
        if self.would_ban {
            return;
        }
        self.ring.push(ts);
        self.would_ban = self.ring.threshold_reached(find_time);
    }
}

/// Matching state and accumulated results for one jail.
pub(crate) struct JailScan<'a> {
    name: &'a str,
    jail: &'a JailConfig,
    matcher: JailMatcher,
    date_parser: DateParser,
    ignore: IgnoreList,
    /// Total non-ignored matches.
    pub(crate) match_count: usize,
    /// Per-IP bounded state.
    pub(crate) ips: HashMap<IpAddr, IpState>,
}

impl<'a> JailScan<'a> {
    /// Build scan state for a jail. An invalid filter is reported on stderr
    /// and the jail skipped (`Ok(None)`), matching prior dry-run behavior.
    fn new(name: &'a str, jail: &'a JailConfig) -> Result<Option<Self>> {
        let matcher = match JailMatcher::new(&jail.filter) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("Jail {name}: invalid filter — {e}");
                return Ok(None);
            }
        };
        Ok(Some(Self {
            name,
            jail,
            matcher,
            date_parser: DateParser::new(jail.date_format)?,
            ignore: IgnoreList::new(&jail.ignoreip, jail.ignoreself)?,
            match_count: 0,
            ips: HashMap::new(),
        }))
    }

    /// Feed one decoded log line through this jail.
    fn scan_line(&mut self, line: &str) {
        let Some(m) = self.matcher.try_match(line) else {
            return;
        };
        if self.ignore.is_ignored(&m.ip) {
            return;
        }
        let ts = self.date_parser.parse_line(line).unwrap_or(0);
        let max_retry = self.jail.max_retry;
        self.ips
            .entry(m.ip)
            .or_insert_with(|| IpState::new(max_retry))
            .record(ts, self.jail.find_time);
        self.match_count += 1;
    }

    /// Number of IPs that would be banned.
    fn would_ban_count(&self) -> usize {
        self.ips.values().filter(|s| s.would_ban).count()
    }
}

/// Build scan state for every enabled jail, optionally restricted to one name.
pub(crate) fn build_scans<'a>(
    config: &'a Config,
    jail_filter: Option<&str>,
) -> Result<Vec<JailScan<'a>>> {
    let mut scans = Vec::new();
    for (name, jail) in config.enabled_jails() {
        if jail_filter.is_some_and(|f| f != name) {
            continue;
        }
        if let Some(scan) = JailScan::new(name, jail)? {
            scans.push(scan);
        }
    }
    Ok(scans)
}

/// Stream `reader` once, feeding each line to every jail. Lines are split on
/// `\n` and decoded lossily. Returns the number of lines read.
pub(crate) fn scan<R: BufRead>(mut reader: R, scans: &mut [JailScan<'_>]) -> Result<usize> {
    let mut buf = Vec::new();
    let mut lines = 0;
    loop {
        buf.clear();
        let n = reader
            .read_until(b'\n', &mut buf)
            .context("reading log line")?;
        if n == 0 {
            return Ok(lines);
        }
        if buf.last() == Some(&b'\n') {
            buf.pop();
        }
        lines += 1;
        let line = lossy(&buf);
        for s in scans.iter_mut() {
            s.scan_line(&line);
        }
    }
}

/// Render the full dry-run report.
pub(crate) fn render(
    out: &mut impl Write,
    log_path: &Path,
    lines: usize,
    scans: &[JailScan<'_>],
) -> std::io::Result<()> {
    writeln!(out, "Dry run — analyzing log without banning anyone.\n")?;
    writeln!(out, "  Log file: {}", log_path.display())?;
    writeln!(out, "  Lines:    {lines}")?;
    writeln!(out)?;
    for s in scans {
        render_jail(out, s)?;
    }
    Ok(())
}

/// Render one jail's summary and per-IP breakdown.
fn render_jail(out: &mut impl Write, s: &JailScan<'_>) -> std::io::Result<()> {
    let jail = s.jail;
    writeln!(out, "Jail: {}", s.name)?;
    writeln!(out, "  Patterns:   {} loaded", jail.filter.len())?;
    writeln!(
        out,
        "  Threshold:  {} failures within {}",
        jail.max_retry, jail.find_time
    )?;
    writeln!(out, "  Ban time:   {}", jail.ban_time)?;
    writeln!(out, "  Matches:    {}", s.match_count)?;
    writeln!(out, "  Unique IPs: {}", s.ips.len())?;
    let would_ban = s.would_ban_count();
    if would_ban > 0 {
        writeln!(out, "  Would ban:  {would_ban}")?;
    }
    if !s.ips.is_empty() {
        writeln!(out)?;
        let mut sorted: Vec<_> = s.ips.iter().collect();
        // Most failures first; ties broken by IP for deterministic output.
        sorted.sort_by(|a, b| b.1.count.cmp(&a.1.count).then_with(|| a.0.cmp(b.0)));
        for (ip, state) in sorted {
            render_ip(out, ip, state, jail)?;
        }
    }
    writeln!(out)
}

/// Render one IP's line.
fn render_ip(
    out: &mut impl Write,
    ip: &IpAddr,
    state: &IpState,
    jail: &JailConfig,
) -> std::io::Result<()> {
    let count = state.count;
    if state.would_ban {
        return writeln!(out, "    {ip}: {count} failures  <- WOULD BAN");
    }
    let max_retry = jail.max_retry as usize;
    if count < max_retry {
        let remaining = max_retry - count;
        return writeln!(out, "    {ip}: {count} failures  ({remaining} more to ban)");
    }
    // Enough failures overall, but never within one find_time window.
    writeln!(
        out,
        "    {ip}: {count} failures  (spread beyond {}s window)",
        jail.find_time
    )
}

/// Run a dry run of `log_path` against the configured jails, printing to stdout.
pub(crate) fn run(config: &Config, log_path: &Path, jail_filter: Option<&str>) -> Result<()> {
    let file = std::fs::File::open(log_path)
        .with_context(|| format!("opening log file: {}", log_path.display()))?;
    let mut scans = build_scans(config, jail_filter)?;
    let lines = scan(BufReader::new(file), &mut scans)?;
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    render(&mut out, log_path, lines, &scans).context("writing dry-run output")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
#[path = "dry_run_test.rs"]
mod dry_run_test;
