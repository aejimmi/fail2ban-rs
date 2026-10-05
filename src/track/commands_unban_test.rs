use super::*;

use std::net::Ipv4Addr;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::enforce::FirewallCmd;
use crate::track::test_support::{test_global_config, test_jail_config, test_store};

#[tokio::test]
async fn test_failed_manual_unban_keeps_record_for_retry() {
    let mut jails = HashMap::new();
    jails.insert("sshd".to_string(), test_jail_config());
    let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77));
    let now = chrono::Utc::now().timestamp();
    let restored = vec![crate::track::state::BanRecord {
        ip,
        jail_id: "sshd".to_string(),
        banned_at: now,
        expires_at: Some(now + 3600),
    }];
    let (_failure_tx, failure_rx) = mpsc::channel(16);
    let (executor_tx, mut executor_rx) = mpsc::channel(16);
    let (cmd_tx, cmd_rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();
    let task = tokio::spawn(crate::track::run(
        test_global_config(),
        jails,
        failure_rx,
        cmd_rx,
        executor_tx,
        false,
        restored,
        HashMap::new(),
        test_store(),
        None,
        cancel.clone(),
    ));
    for should_succeed in [false, true] {
        let (respond, response) = tokio::sync::oneshot::channel();
        cmd_tx
            .send(TrackerCmd::ManualUnban {
                ip,
                jail_id: "sshd".into(),
                respond,
            })
            .await
            .unwrap();
        let FirewallCmd::Unban {
            done: Some(done), ..
        } = executor_rx.recv().await.unwrap()
        else {
            panic!("expected acknowledged unban");
        };
        let backend_result = if should_succeed {
            Ok(())
        } else {
            Err(crate::error::Error::firewall("injected backend failure"))
        };
        done.send(backend_result).unwrap();
        assert_eq!(response.await.unwrap().is_ok(), should_succeed);
        let (respond, bans) = tokio::sync::oneshot::channel();
        cmd_tx
            .send(TrackerCmd::QueryBans { respond })
            .await
            .unwrap();
        assert_eq!(bans.await.unwrap().len(), usize::from(!should_succeed));
    }
    cancel.cancel();
    task.await.unwrap();
}

#[tokio::test]
async fn test_closed_executor_keeps_manual_unban_record() {
    let mut jails = HashMap::new();
    jails.insert("sshd".to_string(), test_jail_config());
    let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 78));
    let now = chrono::Utc::now().timestamp();
    let restored = vec![crate::track::state::BanRecord {
        ip,
        jail_id: "sshd".to_string(),
        banned_at: now,
        expires_at: Some(now + 3600),
    }];
    let (_failure_tx, failure_rx) = mpsc::channel(16);
    let (executor_tx, executor_rx) = mpsc::channel(16);
    drop(executor_rx);
    let (cmd_tx, cmd_rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();
    let task = tokio::spawn(crate::track::run(
        test_global_config(),
        jails,
        failure_rx,
        cmd_rx,
        executor_tx,
        false,
        restored,
        HashMap::new(),
        test_store(),
        None,
        cancel.clone(),
    ));
    let (respond, response) = tokio::sync::oneshot::channel();
    cmd_tx
        .send(TrackerCmd::ManualUnban {
            ip,
            jail_id: "sshd".into(),
            respond,
        })
        .await
        .unwrap();
    assert!(matches!(
        response.await.unwrap(),
        Err(crate::error::Error::ChannelClosed)
    ));
    let (respond, bans) = tokio::sync::oneshot::channel();
    cmd_tx
        .send(TrackerCmd::QueryBans { respond })
        .await
        .unwrap();
    assert_eq!(bans.await.unwrap().len(), 1);
    cancel.cancel();
    task.await.unwrap();
}
