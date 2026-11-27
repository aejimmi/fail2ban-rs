use super::*;

use std::io::{Cursor, Read};

/// Replay a timestamp sequence through [`IpState`].
fn replay(timestamps: &[i64], max_retry: u32, find_time: i64) -> IpState {
    let mut state = IpState::new(max_retry);
    for &ts in timestamps {
        state.record(ts, find_time);
    }
    state
}

/// Pre-streaming reference: keep every timestamp, then replay the ring.
fn legacy_would_ban(timestamps: &[i64], max_retry: u32, find_time: i64) -> bool {
    let mut ring = CircularTimestamps::new(max_retry as usize);
    for &ts in timestamps {
        ring.push(ts);
        if ring.threshold_reached(find_time) {
            return true;
        }
    }
    false
}

/// Pre-streaming reference for one jail: load all lines, collect every
/// timestamp per IP. Returns (match_count, ip -> (count, would_ban)).
fn legacy_jail(lines: &[String], jail: &JailConfig) -> (usize, HashMap<BanTarget, (usize, bool)>) {
    let matcher = JailMatcher::new(&jail.filter).unwrap();
    let parser = DateParser::new(jail.date_format).unwrap();
    let ignore = IgnoreList::new(&jail.ignoreip, jail.ignoreself).unwrap();
    let mut failures: HashMap<BanTarget, Vec<i64>> = HashMap::new();
    let mut matches = 0;
    for line in lines {
        let Some(m) = matcher.try_match(line) else {
            continue;
        };
        if ignore.is_ignored(&m.ip) {
            continue;
        }
        failures
            .entry(m.ip.into())
            .or_default()
            .push(parser.parse_line(line).unwrap_or(0));
        matches += 1;
    }
    let summary = failures
        .iter()
        .map(|(ip, ts)| {
            let ban = legacy_would_ban(ts, jail.max_retry, jail.find_time);
            (*ip, (ts.len(), ban))
        })
        .collect();
    (matches, summary)
}

const SSH_CONFIG: &str = r#"
[global]

[jail.sshd]
log_path = "/var/log/auth.log"
date_format = "syslog"
max_retry = 5
find_time = 600
filter = ['Invalid user .* from <HOST>', 'Failed password for .* from <HOST>']

[jail.sshd-strict]
log_path = "/var/log/auth.log"
date_format = "syslog"
max_retry = 2
find_time = 5
ignoreip = ["183.62.140.253"]
filter = ['authentication failure;.* rhost=<HOST>']
"#;

const SMALL_CONFIG: &str = r#"
[global]

[jail.test]
log_path = "/var/log/test.log"
date_format = "epoch"
max_retry = 3
find_time = 60
ban_time = 3600
ignoreip = ["10.0.0.1"]
filter = ['fail from <HOST>']
"#;

const SMALL_LOG: &str = "\
1700000000 fail from 1.1.1.1
1700000010 fail from 1.1.1.1
1700000020 fail from 1.1.1.1
1700000000 fail from 2.2.2.2
1700000100 fail from 2.2.2.2
1700000200 fail from 2.2.2.2
1700000300 fail from 2.2.2.2
1700000000 fail from 3.3.3.3
1700000000 fail from 10.0.0.1
1700000000 ok from 4.4.4.4
";

fn run_to_string(config: &Config, log: &[u8], filter: Option<&str>) -> String {
    let mut scans = build_scans(config, filter).unwrap();
    let lines = scan(Cursor::new(log), &mut scans).unwrap();
    let mut out = Vec::new();
    render(&mut out, Path::new("test.log"), lines, &scans).unwrap();
    String::from_utf8(out).unwrap()
}

#[test]
fn test_ip_state_bans_when_failures_within_window() {
    let ts: Vec<i64> = (0..5).map(|i| 1_000 + i * 60).collect();
    assert!(replay(&ts, 5, 600).would_ban);
}

#[test]
fn test_ip_state_no_ban_when_spread_beyond_window() {
    let ts: Vec<i64> = (0..5).map(|i| 1_000 + i * 1_000).collect();
    let state = replay(&ts, 5, 600);
    assert!(!state.would_ban);
    assert_eq!(state.count, 5);
}

#[test]
fn test_ip_state_no_ban_below_max_retry() {
    assert!(!replay(&[1_000, 1_010, 1_020], 5, 600).would_ban);
}

#[test]
fn test_ip_state_ban_from_late_burst_after_early_spread() {
    let ts = [0, 5_000, 10_000, 10_001, 10_002, 10_003, 10_004];
    assert!(replay(&ts, 5, 600).would_ban);
}

#[test]
fn test_ip_state_ban_is_sticky_and_count_continues() {
    let ts = [0, 1, 2, 100_000, 200_000];
    let state = replay(&ts, 3, 10);
    assert!(state.would_ban);
    assert_eq!(state.count, 5);
}

#[test]
fn test_ip_state_matches_legacy_on_varied_sequences() {
    let seqs: [&[i64]; 5] = [
        &[],
        &[0, 0, 0],
        &[50, 10, 30, 20, 40],
        &[0, 700, 1_300, 1_301, 1_302, 5_000],
        &[9, 8, 7, 6, 5, 4, 3, 2, 1],
    ];
    for seq in seqs {
        for max_retry in [0, 1, 2, 3, 5] {
            let got = replay(seq, max_retry, 600).would_ban;
            let want = legacy_would_ban(seq, max_retry, 600);
            assert_eq!(got, want, "seq {seq:?} max_retry {max_retry}");
        }
    }
}

#[test]
fn test_scan_line_count_matches_split_semantics() {
    let config = Config::parse(SMALL_CONFIG).unwrap();
    for (input, want) in [
        (&b""[..], 0),
        (&b"a"[..], 1),
        (&b"a\n"[..], 1),
        (&b"a\nb"[..], 2),
        (&b"a\n\n"[..], 2),
        (&b"\n\n\n"[..], 3),
    ] {
        let mut scans = build_scans(&config, None).unwrap();
        let lines = scan(Cursor::new(input), &mut scans).unwrap();
        let legacy = BufReader::new(input).split(b'\n').count();
        assert_eq!(lines, want, "input {input:?}");
        assert_eq!(lines, legacy, "input {input:?}");
    }
}

#[test]
fn test_scan_decodes_invalid_utf8_lossily() {
    let config = Config::parse(SMALL_CONFIG).unwrap();
    let mut scans = build_scans(&config, None).unwrap();
    let log = b"1000 fail from 5.5.5.5 \xff\xfe\n";
    let lines = scan(Cursor::new(&log[..]), &mut scans).unwrap();
    assert_eq!(lines, 1);
    assert_eq!(scans[0].match_count, 1);
}

#[test]
fn test_render_small_log_golden_output() {
    let config = Config::parse(SMALL_CONFIG).unwrap();
    let got = run_to_string(&config, SMALL_LOG.as_bytes(), None);
    let want = "\
Dry run — analyzing log without banning anyone.

  Log file: test.log
  Lines:    10

Jail: test
  Patterns:   1 loaded
  Threshold:  3 failures within 60
  Ban time:   3600
  Matches:    8
  Unique IPs: 3
  Would ban:  1

    2.2.2.2: 4 failures  (spread beyond 60s window)
    1.1.1.1: 3 failures  <- WOULD BAN
    3.3.3.3: 1 failures  (2 more to ban)

";
    assert_eq!(got, want);
}

#[test]
fn test_build_scans_jail_filter_selects_one() {
    let config = Config::parse(SSH_CONFIG).unwrap();
    let scans = build_scans(&config, Some("sshd")).unwrap();
    assert_eq!(scans.len(), 1);
    assert!(build_scans(&config, Some("missing")).unwrap().is_empty());
    assert_eq!(build_scans(&config, None).unwrap().len(), 2);
}

#[test]
fn test_scan_matches_legacy_on_sample_log() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("sample/openssh_2k.log");
    let bytes = std::fs::read(&path).unwrap();
    let config = Config::parse(SSH_CONFIG).unwrap();

    let mut scans = build_scans(&config, None).unwrap();
    let lines = scan(Cursor::new(&bytes), &mut scans).unwrap();

    let all: Vec<String> = BufReader::new(&bytes[..])
        .split(b'\n')
        .map(|l| String::from_utf8_lossy(&l.unwrap()).into_owned())
        .collect();
    assert_eq!(lines, all.len());

    let mut total_matches = 0;
    for s in &scans {
        let (matches, legacy) = legacy_jail(&all, s.jail);
        assert_eq!(s.match_count, matches, "jail {}", s.name);
        assert_eq!(s.ips.len(), legacy.len(), "jail {}", s.name);
        for (ip, state) in &s.ips {
            assert_eq!(Some(&(state.count, state.would_ban)), legacy.get(ip));
        }
        total_matches += matches;
    }
    assert!(total_matches > 100, "sample should exercise matching");
}

/// Lazily generates `remaining` log lines without materializing the file.
struct LineGen {
    remaining: usize,
    pending: Vec<u8>,
}

impl Read for LineGen {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if self.pending.is_empty() {
            if self.remaining == 0 {
                return Ok(0);
            }
            let n = self.remaining;
            self.remaining -= 1;
            let line = format!("{} fail from 7.7.7.{}\n", 1_700_000_000 + n, n % 4);
            self.pending.extend_from_slice(line.as_bytes());
        }
        let k = out.len().min(self.pending.len());
        out[..k].copy_from_slice(&self.pending[..k]);
        self.pending.drain(..k);
        Ok(k)
    }
}

#[test]
fn test_scan_large_stream_keeps_bounded_state() {
    let config = Config::parse(SMALL_CONFIG).unwrap();
    let mut scans = build_scans(&config, None).unwrap();
    let total = 200_000;
    let reader = BufReader::new(LineGen {
        remaining: total,
        pending: Vec::new(),
    });
    let lines = scan(reader, &mut scans).unwrap();
    assert_eq!(lines, total);
    let s = &scans[0];
    assert_eq!(s.match_count, total);
    // State is per unique IP, independent of line count.
    assert_eq!(s.ips.len(), 4);
    assert!(
        s.ips
            .values()
            .all(|st| st.count == total / 4 && st.would_ban)
    );
}

#[test]
fn test_run_missing_log_errors() {
    let config = Config::parse(SMALL_CONFIG).unwrap();
    let dir = tempfile::TempDir::new().unwrap();
    let err = run(&config, &dir.path().join("nope.log"), None).unwrap_err();
    assert!(format!("{err:#}").contains("opening log file"));
}
