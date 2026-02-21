//! Tests for webhook notification.

// Webhook functions spawn tokio tasks that call curl, so we can only
// test that they don't panic. The actual HTTP POST is not tested here
// (would need a test server).

use std::net::{IpAddr, Ipv4Addr};

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
