use super::*;

#[test]
fn would_ban_when_failures_within_window() {
    // 5 failures, each 60s apart → 240s span, inside a 600s window.
    let ts: Vec<i64> = (0..5).map(|i| 1_000 + i * 60).collect();
    assert!(ip_would_ban(&ts, 5, 600));
}

#[test]
fn no_ban_when_failures_spread_beyond_window() {
    // 5 failures 1000s apart → never 5 within a 600s window, despite the
    // total count meeting max_retry.
    let ts: Vec<i64> = (0..5).map(|i| 1_000 + i * 1_000).collect();
    assert!(!ip_would_ban(&ts, 5, 600));
}

#[test]
fn no_ban_below_max_retry() {
    // Only 3 failures but max_retry is 5 — never reaches the threshold.
    let ts = vec![1_000, 1_010, 1_020];
    assert!(!ip_would_ban(&ts, 5, 600));
}

#[test]
fn ban_from_late_burst_after_early_spread() {
    // Early spread-out failures then a tight burst of five within the
    // window. The ring holds the most recent max_retry entries, so once
    // the last five fall inside find_time the threshold trips.
    let ts = vec![0, 5_000, 10_000, 10_001, 10_002, 10_003, 10_004];
    assert!(ip_would_ban(&ts, 5, 600));
}
