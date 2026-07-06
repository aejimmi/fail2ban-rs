use super::*;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

use crate::config::JailConfig;
use crate::enforce::test_support::{FailingMockBackend, MockBackend};
use crate::track::state::BanRecord;

/// Build a default jail configs map with reban_on_restart enabled for "sshd".
fn default_jail_configs() -> HashMap<String, JailConfig> {
    let mut m = HashMap::new();
    m.insert("sshd".to_string(), test_jail_config(true));
    m
}

fn test_jail_config(restore: bool) -> JailConfig {
    JailConfig {
        enabled: true,
        log_path: "/tmp/test.log".into(),
        date_format: crate::detect::date::DateFormat::Syslog,
        filter: vec!["from <HOST>".to_string()],
        max_retry: 3,
        find_time: 600,
        ban_time: 60,
        port: vec![],
        protocol: "tcp".to_string(),
        bantime_increment: false,
        bantime_factor: 1.0,
        bantime_multipliers: vec![],
        bantime_maxtime: 604_800,
        backend: crate::config::Backend::Nftables,
        log_backend: crate::config::LogBackend::default(),
        journalmatch: vec![],
        ignoreregex: vec![],
        ignoreip: vec![],
        ignoreself: false,
        reban_on_restart: restore,
        webhook: None,
        maxmind: vec![],
    }
}

#[tokio::test]
async fn restore_bans_skips_expired() {
    let (backend, calls) = MockBackend::new();
    let now = chrono::Utc::now().timestamp();

    let mut backends: HashMap<String, Box<dyn FirewallBackend>> = HashMap::new();
    backends.insert("sshd".to_string(), Box::new(backend));

    let bans = vec![
        BanRecord {
            ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            jail_id: "sshd".to_string(),
            banned_at: now - 7200,
            expires_at: Some(now - 3600), // expired 1 hour ago
        },
        BanRecord {
            ip: IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)),
            jail_id: "sshd".to_string(),
            banned_at: now - 1800,
            expires_at: Some(now + 1800), // still active
        },
    ];

    let jail_configs = default_jail_configs();
    let restored = crate::enforce::restore_bans(&bans, &backends, now, &jail_configs).await;

    assert_eq!(restored.len(), 1);
    assert_eq!(restored[0].ip, IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)));

    let calls = calls.lock().expect("lock");
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0], "ban:2.2.2.2:sshd");
}

#[tokio::test]
async fn init_and_restore_inits_before_restored_ban() {
    let (backend, calls) = MockBackend::new();
    let now = chrono::Utc::now().timestamp();

    let mut backends: HashMap<String, Box<dyn FirewallBackend>> = HashMap::new();
    backends.insert("sshd".to_string(), Box::new(backend));

    let bans = vec![BanRecord {
        ip: IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
        jail_id: "sshd".to_string(),
        banned_at: now - 60,
        expires_at: Some(now + 3600),
    }];

    let jail_configs = default_jail_configs();
    let restored = crate::enforce::init_and_restore(&bans, &backends, now, &jail_configs)
        .await
        .expect("init_and_restore");
    assert_eq!(restored.len(), 1);

    let calls = calls.lock().expect("lock");
    let init_idx = calls
        .iter()
        .position(|c| c.starts_with("init:"))
        .expect("init recorded");
    let ban_idx = calls
        .iter()
        .position(|c| c.starts_with("ban:"))
        .expect("ban recorded");
    assert!(
        init_idx < ban_idx,
        "init must precede restored ban: {calls:?}"
    );
}

#[tokio::test]
async fn restore_bans_keeps_permanent() {
    let (backend, calls) = MockBackend::new();
    let now = chrono::Utc::now().timestamp();

    let mut backends: HashMap<String, Box<dyn FirewallBackend>> = HashMap::new();
    backends.insert("sshd".to_string(), Box::new(backend));

    let bans = vec![BanRecord {
        ip: IpAddr::V4(Ipv4Addr::new(3, 3, 3, 3)),
        jail_id: "sshd".to_string(),
        banned_at: now - 86400,
        expires_at: None, // permanent
    }];

    let jail_configs = default_jail_configs();
    let restored = crate::enforce::restore_bans(&bans, &backends, now, &jail_configs).await;
    assert_eq!(restored.len(), 1);

    let calls = calls.lock().expect("lock");
    assert_eq!(calls[0], "ban:3.3.3.3:sshd");
}

#[tokio::test]
async fn restore_bans_empty() {
    let backends: HashMap<String, Box<dyn FirewallBackend>> = HashMap::new();
    let now = chrono::Utc::now().timestamp();

    let jail_configs = default_jail_configs();
    let restored = crate::enforce::restore_bans(&[], &backends, now, &jail_configs).await;
    assert!(restored.is_empty());
}

#[tokio::test]
async fn restore_bans_skips_on_backend_error() {
    let mut backends: HashMap<String, Box<dyn FirewallBackend>> = HashMap::new();
    backends.insert("sshd".to_string(), Box::new(FailingMockBackend));
    let now = chrono::Utc::now().timestamp();

    let bans = vec![BanRecord {
        ip: IpAddr::V4(Ipv4Addr::new(4, 4, 4, 4)),
        jail_id: "sshd".to_string(),
        banned_at: now,
        expires_at: Some(now + 3600),
    }];

    let jail_configs = default_jail_configs();
    let restored = crate::enforce::restore_bans(&bans, &backends, now, &jail_configs).await;
    assert!(restored.is_empty(), "should skip on backend error");
}

#[tokio::test]
async fn restore_bans_skips_jail_with_restore_disabled() {
    let (backend, calls) = MockBackend::new();
    let now = chrono::Utc::now().timestamp();

    let mut backends: HashMap<String, Box<dyn FirewallBackend>> = HashMap::new();
    backends.insert("sshd".to_string(), Box::new(backend));

    let bans = vec![BanRecord {
        ip: IpAddr::V4(Ipv4Addr::new(5, 5, 5, 5)),
        jail_id: "sshd".to_string(),
        banned_at: now - 60,
        expires_at: Some(now + 3600),
    }];

    // Jail has reban_on_restart = false.
    let mut jail_configs = HashMap::new();
    jail_configs.insert("sshd".to_string(), test_jail_config(false));

    let restored = crate::enforce::restore_bans(&bans, &backends, now, &jail_configs).await;
    assert!(
        restored.is_empty(),
        "should skip jail with reban_on_restart=false"
    );

    let calls = calls.lock().expect("lock");
    assert!(calls.is_empty(), "ban command should not be called");
}

#[tokio::test]
async fn restore_bans_mixed_jails() {
    let sshd_calls = Arc::new(Mutex::new(Vec::new()));
    let nginx_calls = Arc::new(Mutex::new(Vec::new()));

    let mut backends: HashMap<String, Box<dyn FirewallBackend>> = HashMap::new();
    backends.insert(
        "sshd".to_string(),
        Box::new(MockBackend {
            calls: Arc::clone(&sshd_calls),
        }),
    );
    backends.insert(
        "nginx".to_string(),
        Box::new(MockBackend {
            calls: Arc::clone(&nginx_calls),
        }),
    );

    let now = chrono::Utc::now().timestamp();
    let bans = vec![
        BanRecord {
            ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            jail_id: "sshd".to_string(),
            banned_at: now - 60,
            expires_at: Some(now + 3600),
        },
        BanRecord {
            ip: IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)),
            jail_id: "nginx".to_string(),
            banned_at: now - 60,
            expires_at: Some(now + 3600),
        },
    ];

    // sshd: reban_on_restart=false, nginx: reban_on_restart=true
    let mut jail_configs = HashMap::new();
    jail_configs.insert("sshd".to_string(), test_jail_config(false));
    jail_configs.insert("nginx".to_string(), test_jail_config(true));

    let restored = crate::enforce::restore_bans(&bans, &backends, now, &jail_configs).await;
    assert_eq!(restored.len(), 1);
    assert_eq!(restored[0].ip, IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)));

    let sshd = sshd_calls.lock().expect("lock");
    assert!(sshd.is_empty(), "sshd should be skipped");

    let nginx = nginx_calls.lock().expect("lock");
    assert_eq!(nginx.len(), 1);
    assert_eq!(nginx[0], "ban:2.2.2.2:nginx");
}
