use super::*;

// Webhook functions spawn tokio tasks that call curl, so we can only
// test that they don't panic. The actual HTTP POST is not tested here
// (would need a test server). Argument construction and URL validation
// are pure and tested directly below.

use std::net::Ipv4Addr;

use crate::ban_target::BanTarget;

#[test]
fn is_http_url_accepts_http_and_https() {
    assert!(is_http_url("http://example.com/hook"));
    assert!(is_http_url("https://example.com/hook"));
}

#[test]
fn is_http_url_rejects_option_laundering() {
    // A URL that begins with `-` must never be accepted, since curl would
    // otherwise interpret it as an option.
    assert!(!is_http_url("-o/etc/cron.d/x"));
    assert!(!is_http_url("-K/tmp/evil"));
}

#[test]
fn is_http_url_rejects_non_http_schemes() {
    assert!(!is_http_url("file:///etc/passwd"));
    assert!(!is_http_url("gopher://evil/"));
    assert!(!is_http_url("dict://evil/"));
    assert!(!is_http_url("ftp://evil/"));
}

#[test]
fn curl_args_terminates_options_before_url() {
    let args = curl_args("{}", "http://example.com/hook");
    // The URL must be the final positional argument, immediately preceded
    // by the `--` option terminator.
    assert_eq!(args.last().copied(), Some("http://example.com/hook"));
    let terminator = args.len() - 2;
    assert_eq!(args.get(terminator).copied(), Some("--"));
}

#[test]
fn curl_args_sets_max_time() {
    let args = curl_args("{}", "http://example.com/hook");
    let idx = args.iter().position(|a| *a == "--max-time");
    assert!(idx.is_some(), "expected --max-time in {args:?}");
    assert_eq!(args.get(idx.unwrap() + 1).copied(), Some("10"));
}

#[test]
fn curl_args_places_body_after_data_flag() {
    let args = curl_args("payload", "http://example.com/hook");
    let idx = args.iter().position(|a| *a == "-d").unwrap();
    assert_eq!(args.get(idx + 1).copied(), Some("payload"));
}

#[tokio::test]
async fn notify_ban_does_not_panic() {
    // Use an invalid URL — the curl call will fail, but it should
    // not panic or block.
    crate::webhook::notify_ban(
        "http://127.0.0.1:1/test",
        BanTarget::V4(Ipv4Addr::new(1, 2, 3, 4)),
        "sshd",
        3600,
    );
    // Give the spawned task a moment to run.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
}

#[tokio::test]
async fn notify_unban_does_not_panic() {
    crate::webhook::notify_unban(
        "http://127.0.0.1:1/test",
        BanTarget::V4(Ipv4Addr::new(5, 6, 7, 8)),
        "nginx",
    );
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
}

#[test]
fn test_curl_args_discards_response_body() {
    let args = curl_args("{}", "http://example.com/hook");
    let idx = args.iter().position(|a| *a == "-o").unwrap();
    assert_eq!(args.get(idx + 1).copied(), Some("/dev/null"));
}

#[test]
fn test_limiter_admits_up_to_pending_then_drops() {
    let limiter = Limiter::new(2, 5);
    let tickets: Vec<Ticket> = (0..5).map(|_| limiter.try_admit().unwrap()).collect();
    assert!(
        limiter.try_admit().is_none(),
        "6th admission must be dropped"
    );
    drop(tickets);
    assert!(
        limiter.try_admit().is_some(),
        "capacity returns after release"
    );
}

#[test]
fn test_limiter_burst_admits_exactly_pending() {
    let limiter = Limiter::new(MAX_CONCURRENT, MAX_PENDING);
    let mut held = Vec::new();
    let mut dropped = 0;
    for _ in 0..10_000 {
        match limiter.try_admit() {
            Some(t) => held.push(t),
            None => dropped += 1,
        }
    }
    assert_eq!(held.len(), MAX_PENDING);
    assert_eq!(dropped, 10_000 - MAX_PENDING);
}

#[test]
fn test_limiter_pending_never_below_concurrency() {
    let limiter = Limiter::new(4, 1);
    let held: Vec<Ticket> = (0..4).map(|_| limiter.try_admit().unwrap()).collect();
    assert!(limiter.try_admit().is_none());
    assert_eq!(held.len(), 4);
}

#[tokio::test]
async fn test_limiter_bounds_concurrent_slots() {
    let limiter = Limiter::new(2, 10);
    let tickets: Vec<Ticket> = (0..3).map(|_| limiter.try_admit().unwrap()).collect();
    let s1 = tickets[0].run_slot().await.unwrap();
    let _s2 = tickets[1].run_slot().await.unwrap();
    let wait = std::time::Duration::from_millis(50);
    let third = tokio::time::timeout(wait, tickets[2].run_slot()).await;
    assert!(third.is_err(), "third slot must wait while two are running");
    drop(s1);
    let wait = std::time::Duration::from_millis(500);
    let third = tokio::time::timeout(wait, tickets[2].run_slot()).await;
    assert!(third.unwrap().is_some(), "slot frees after a delivery ends");
}

#[tokio::test]
async fn test_read_capped_truncates_large_output() {
    let data = vec![b'x'; 1_000_000];
    let out = read_capped(&data[..], STDERR_CAP).await;
    assert_eq!(out.len() as u64, STDERR_CAP);
}

#[tokio::test]
async fn test_read_capped_short_output_intact() {
    let out = read_capped(&b"curl: (7) refused"[..], STDERR_CAP).await;
    assert_eq!(out, "curl: (7) refused");
}

#[tokio::test]
async fn test_notify_ban_burst_does_not_block() {
    let start = std::time::Instant::now();
    for i in 0..1_000u32 {
        crate::webhook::notify_ban(
            "http://127.0.0.1:1/test",
            BanTarget::V4(Ipv4Addr::from(i)),
            "sshd",
            60,
        );
    }
    assert!(
        start.elapsed() < std::time::Duration::from_secs(2),
        "burst dispatch must return promptly"
    );
}
