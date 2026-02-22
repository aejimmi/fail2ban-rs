//! Criterion benchmarks for the matching pipeline.
//!
//! Measures per-line nanoseconds for each code path through
//! `JailMatcher::try_match()` using real log line patterns.

use criterion::{Criterion, black_box, criterion_group, criterion_main};

use fail2ban_rs::date::{DateFormat, DateParser};
use fail2ban_rs::matcher::JailMatcher;

// ---------------------------------------------------------------------------
// Real line patterns — each exercises a different code path.
// ---------------------------------------------------------------------------

/// Matches sshd pattern 2: "Invalid user .* from <HOST>"
const HIT_INVALID_USER: &str = "2026-02-15T00:01:46.515991+00:00 api \
    sshd[203661]: Invalid user banxgg from 80.94.92.184 port 55708";

/// Matches sshd pattern 3: "Connection closed by authenticating user .* <HOST>"
const HIT_CONN_CLOSED_AUTH: &str = "2026-02-15T00:00:36.396434+00:00 api \
    sshd[203657]: Connection closed by authenticating user root \
    103.174.103.249 port 58414 [preauth]";

/// Non-matching: CRON line — no sshd content at all.
const MISS_CRON: &str = "2026-02-15T00:05:01.699457+00:00 api \
    CRON[203684]: pam_unix(cron:session): session opened for user \
    root(uid=0) by root(uid=0)";

/// Non-matching near-miss: contains "sshd" and an IP but pattern says
/// "authenticating user", not "invalid user" after "Connection closed by".
const MISS_CONN_CLOSED_INVALID: &str = "2026-02-15T00:01:46.694556+00:00 api \
    sshd[203661]: Connection closed by invalid user banxgg 80.94.92.184 \
    port 55708 [preauth]";

/// Non-matching near-miss: "Connection reset" vs pattern's "Connection closed".
const MISS_CONN_RESET: &str = "2026-02-15T00:11:49.416926+00:00 api \
    sshd[203717]: Connection reset by authenticating user root \
    176.120.22.47 port 27094 [preauth]";

// ---------------------------------------------------------------------------
// Helper: build the sshd matcher with the same patterns as filters.rs
// ---------------------------------------------------------------------------

fn sshd_matcher() -> JailMatcher {
    let patterns: Vec<String> = vec![
        r#"sshd\[\d+\]: Failed password for .* from <HOST> port \d+"#,
        r#"sshd\[\d+\]: Invalid user .* from <HOST> port \d+"#,
        r#"sshd\[\d+\]: Connection closed by authenticating user .* <HOST> port \d+"#,
        r#"sshd\[\d+\]: Disconnected from authenticating user .* <HOST> port \d+"#,
    ]
    .into_iter()
    .map(String::from)
    .collect();
    JailMatcher::new(&patterns).expect("sshd patterns must compile")
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

fn bench_try_match(c: &mut Criterion) {
    let matcher = sshd_matcher();

    let mut group = c.benchmark_group("try_match");

    group.bench_function("hit_invalid_user", |b| {
        b.iter(|| matcher.try_match(black_box(HIT_INVALID_USER)))
    });

    group.bench_function("hit_conn_closed_auth", |b| {
        b.iter(|| matcher.try_match(black_box(HIT_CONN_CLOSED_AUTH)))
    });

    group.bench_function("miss_cron", |b| {
        b.iter(|| matcher.try_match(black_box(MISS_CRON)))
    });

    group.bench_function("miss_near_invalid_user", |b| {
        b.iter(|| matcher.try_match(black_box(MISS_CONN_CLOSED_INVALID)))
    });

    group.bench_function("miss_near_conn_reset", |b| {
        b.iter(|| matcher.try_match(black_box(MISS_CONN_RESET)))
    });

    group.finish();
}

fn bench_date_parse(c: &mut Criterion) {
    let parser = DateParser::new(DateFormat::Iso8601).expect("iso8601 parser");

    let mut group = c.benchmark_group("date_parse");

    group.bench_function("iso8601", |b| {
        b.iter(|| parser.parse_line(black_box(HIT_INVALID_USER)))
    });

    group.finish();
}

fn bench_full_pipeline(c: &mut Criterion) {
    let matcher = sshd_matcher();
    let parser = DateParser::new(DateFormat::Iso8601).expect("iso8601 parser");

    // Realistic mix: ~30% hits, ~70% near-misses — mirrors the line
    // distribution in openssh_2k.log (logpai/loghub OpenSSH dataset).
    let lines: Vec<&str> = vec![
        HIT_CONN_CLOSED_AUTH,
        HIT_INVALID_USER,
        HIT_CONN_CLOSED_AUTH,
        MISS_CONN_CLOSED_INVALID,
        MISS_CONN_CLOSED_INVALID,
        MISS_CONN_CLOSED_INVALID,
        MISS_CONN_RESET,
        MISS_CONN_RESET,
        MISS_CONN_CLOSED_INVALID,
        MISS_CONN_RESET,
    ];

    c.bench_function("pipeline_mixed_10_lines", |b| {
        b.iter(|| {
            for line in &lines {
                let _ = parser.parse_line(black_box(line));
                let _ = matcher.try_match(black_box(line));
            }
        })
    });
}

criterion_group!(
    benches,
    bench_try_match,
    bench_date_parse,
    bench_full_pipeline
);
criterion_main!(benches);
