//! Tests for state persistence.

use std::net::{IpAddr, Ipv4Addr};

use crate::state::{self, BanRecord, StateSnapshot};

fn sample_snapshot() -> StateSnapshot {
    StateSnapshot {
        bans: vec![
            BanRecord {
                ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                jail_id: "sshd".to_string(),
                banned_at: 1705312200,
                expires_at: Some(1705315800),
            },
            BanRecord {
                ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 50)),
                jail_id: "nginx".to_string(),
                banned_at: 1705312300,
                expires_at: None, // permanent
            },
        ],
        ban_counts: vec![],
        snapshot_time: 1705312400,
    }
}

#[test]
fn roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.bin");
    let snapshot = sample_snapshot();

    state::save(&path, &snapshot).unwrap();
    let loaded = state::load(&path).unwrap().unwrap();

    assert_eq!(loaded.bans.len(), 2);
    assert_eq!(loaded.bans[0], snapshot.bans[0]);
    assert_eq!(loaded.bans[1], snapshot.bans[1]);
    assert_eq!(loaded.snapshot_time, snapshot.snapshot_time);
}

#[test]
fn missing_file_returns_none() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nonexistent.bin");
    let result = state::load(&path).unwrap();
    assert!(result.is_none());
}

#[test]
fn corrupt_crc() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.bin");
    state::save(&path, &sample_snapshot()).unwrap();

    // Corrupt a byte in the payload.
    let mut data = std::fs::read(&path).unwrap();
    let last = data.len() - 1;
    data[last] ^= 0xFF;
    std::fs::write(&path, &data).unwrap();

    let result = state::load(&path);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("CRC") || err.contains("corrupt"), "got: {err}");
}

#[test]
fn wrong_magic() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.bin");
    state::save(&path, &sample_snapshot()).unwrap();

    let mut data = std::fs::read(&path).unwrap();
    data[0] = b'X';
    std::fs::write(&path, &data).unwrap();

    let result = state::load(&path);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("magic"));
}

#[test]
fn wrong_version() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.bin");
    state::save(&path, &sample_snapshot()).unwrap();

    let mut data = std::fs::read(&path).unwrap();
    data[4] = 99; // bad version
    std::fs::write(&path, &data).unwrap();

    let result = state::load(&path);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("version"));
}

#[test]
fn file_too_small() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.bin");
    std::fs::write(&path, b"tiny").unwrap();

    let result = state::load(&path);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("small"));
}

#[test]
fn empty_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.bin");
    let snapshot = StateSnapshot {
        bans: vec![],
        ban_counts: vec![],
        snapshot_time: 1705312400,
    };

    state::save(&path, &snapshot).unwrap();
    let loaded = state::load(&path).unwrap().unwrap();
    assert!(loaded.bans.is_empty());
}

#[test]
fn roundtrip_ipv6() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.bin");

    let ipv6: IpAddr = "2001:db8::1".parse().unwrap();
    let snapshot = StateSnapshot {
        bans: vec![BanRecord {
            ip: ipv6,
            jail_id: "sshd".to_string(),
            banned_at: 1000,
            expires_at: None,
        }],
        ban_counts: vec![],
        snapshot_time: 2000,
    };

    state::save(&path, &snapshot).unwrap();
    let loaded = state::load(&path).unwrap().unwrap();
    assert_eq!(loaded.bans.len(), 1);
    assert_eq!(loaded.bans[0].ip, ipv6);
    assert!(loaded.bans[0].expires_at.is_none());
}

#[test]
fn overwrite_existing_state() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.bin");

    let snap1 = StateSnapshot {
        bans: vec![BanRecord {
            ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            jail_id: "a".to_string(),
            banned_at: 100,
            expires_at: Some(200),
        }],
        ban_counts: vec![],
        snapshot_time: 100,
    };
    state::save(&path, &snap1).unwrap();

    let snap2 = StateSnapshot {
        bans: vec![BanRecord {
            ip: IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)),
            jail_id: "b".to_string(),
            banned_at: 300,
            expires_at: Some(400),
        }],
        ban_counts: vec![],
        snapshot_time: 300,
    };
    state::save(&path, &snap2).unwrap();

    let loaded = state::load(&path).unwrap().unwrap();
    assert_eq!(loaded.bans.len(), 1);
    assert_eq!(loaded.bans[0].ip, IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)));
    assert_eq!(loaded.snapshot_time, 300);
}
