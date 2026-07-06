use super::*;

// Webhook functions spawn tokio tasks that call curl, so we can only
// test that they don't panic. The actual HTTP POST is not tested here
// (would need a test server). Argument construction and URL validation
// are pure and tested directly below.

use std::net::{IpAddr, Ipv4Addr};

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
        IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
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
        IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
        "nginx",
    );
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
}
