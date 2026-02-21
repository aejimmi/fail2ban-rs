//! Tests for the watcher module.

use std::io::Write;

use tempfile::NamedTempFile;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::date::{DateFormat, DateParser};
use crate::ignore::IgnoreList;
use crate::matcher::JailMatcher;
use crate::watcher;

fn test_matcher() -> JailMatcher {
    JailMatcher::new(&[r"Failed password for .* from <HOST>".to_string()]).unwrap()
}

#[tokio::test]
async fn detects_failure_in_appended_lines() {
    let mut tmpfile = NamedTempFile::new().unwrap();
    let path = tmpfile.path().to_path_buf();

    let (tx, mut rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();

    let cancel_clone = cancel.clone();
    let path_clone = path.clone();
    let handle = tokio::spawn(async move {
        watcher::run(
            "test".to_string(),
            path_clone,
            test_matcher(),
            DateParser::new(DateFormat::Syslog).unwrap(),
            IgnoreList::new(&[], false).unwrap(),
            tx,
            cancel_clone,
        )
        .await;
    });

    // Give watcher time to start and seek to end.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Append a matching line.
    writeln!(
        tmpfile,
        "Jan 15 10:30:00 server sshd[1234]: Failed password for root from 192.168.1.100 port 22"
    )
    .unwrap();
    tmpfile.flush().unwrap();

    // Wait for watcher to pick it up.
    let failure = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
        .await
        .expect("timeout waiting for failure")
        .expect("channel closed");

    assert_eq!(failure.ip.to_string(), "192.168.1.100");
    assert_eq!(failure.jail_id, "test");

    cancel.cancel();
    handle.await.unwrap();
}

#[tokio::test]
async fn ignores_non_matching_lines() {
    let mut tmpfile = NamedTempFile::new().unwrap();
    let path = tmpfile.path().to_path_buf();

    let (tx, mut rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();

    let cancel_clone = cancel.clone();
    let path_clone = path.clone();
    let handle = tokio::spawn(async move {
        watcher::run(
            "test".to_string(),
            path_clone,
            test_matcher(),
            DateParser::new(DateFormat::Syslog).unwrap(),
            IgnoreList::new(&[], false).unwrap(),
            tx,
            cancel_clone,
        )
        .await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Append a non-matching line.
    writeln!(
        tmpfile,
        "Jan 15 10:30:00 server sshd[1234]: Accepted password for user from 10.0.0.1 port 22"
    )
    .unwrap();
    tmpfile.flush().unwrap();

    // Should not receive anything.
    let result = tokio::time::timeout(std::time::Duration::from_millis(500), rx.recv()).await;
    assert!(result.is_err(), "should not have received a failure");

    cancel.cancel();
    handle.await.unwrap();
}

#[tokio::test]
async fn ignores_allowlisted_ips() {
    let mut tmpfile = NamedTempFile::new().unwrap();
    let path = tmpfile.path().to_path_buf();

    let (tx, mut rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();

    let cancel_clone = cancel.clone();
    let path_clone = path.clone();
    let handle = tokio::spawn(async move {
        watcher::run(
            "test".to_string(),
            path_clone,
            test_matcher(),
            DateParser::new(DateFormat::Syslog).unwrap(),
            IgnoreList::new(&["192.168.1.0/24".to_string()], false).unwrap(),
            tx,
            cancel_clone,
        )
        .await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    writeln!(
        tmpfile,
        "Jan 15 10:30:00 server sshd[1234]: Failed password for root from 192.168.1.100 port 22"
    )
    .unwrap();
    tmpfile.flush().unwrap();

    let result = tokio::time::timeout(std::time::Duration::from_millis(500), rx.recv()).await;
    assert!(result.is_err(), "ignored IP should not produce a failure");

    cancel.cancel();
    handle.await.unwrap();
}
