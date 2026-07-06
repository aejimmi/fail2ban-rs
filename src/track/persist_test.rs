use super::*;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use etchdb::{Replayable, Store, Transactable, WalBackend};
use serde::{Deserialize, Serialize};

use crate::track::state::BanRecord;

/// Open (or reopen) a WAL-backed store rooted at `dir`.
fn open(dir: &std::path::Path) -> Store<BanState, WalBackend<BanState>> {
    Store::<BanState, WalBackend<BanState>>::open_wal(dir.to_path_buf()).expect("open WAL store")
}

#[test]
fn round_trip_preserves_bans_and_counts_across_reopen() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ipv4 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let ipv6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));

    {
        let store = open(dir.path());
        store
            .write(|tx| {
                tx.bans.put(
                    (ipv4, "sshd".to_string()),
                    BanRecord {
                        ip: ipv4,
                        jail_id: "sshd".to_string(),
                        banned_at: 1_000,
                        expires_at: Some(1_600),
                    },
                );
                tx.bans.put(
                    (ipv6, "nginx".to_string()),
                    BanRecord {
                        ip: ipv6,
                        jail_id: "nginx".to_string(),
                        banned_at: 2_000,
                        expires_at: None, // permanent ban
                    },
                );
                tx.ban_counts.put(
                    ipv4,
                    BanCount {
                        count: 3,
                        last_ban: 1_000,
                    },
                );
                tx.ban_counts.put(
                    ipv6,
                    BanCount {
                        count: 1,
                        last_ban: 2_000,
                    },
                );
                Ok(())
            })
            .expect("write");
        // `store` dropped here, releasing the WAL file before reopening.
    }

    let reopened = open(dir.path());
    let state = reopened.read();

    let v4_ban = state
        .bans
        .get(&(ipv4, "sshd".to_string()))
        .expect("ipv4 ban restored");
    assert_eq!(v4_ban.banned_at, 1_000);
    assert_eq!(v4_ban.expires_at, Some(1_600));

    let v6_ban = state
        .bans
        .get(&(ipv6, "nginx".to_string()))
        .expect("ipv6 ban restored");
    assert_eq!(
        v6_ban.expires_at, None,
        "permanent ban must round-trip as None, not an expired timestamp"
    );

    assert_eq!(state.ban_counts.get(&ipv4).map(|bc| bc.count), Some(3));
    assert_eq!(
        state.ban_counts.get(&ipv4).map(|bc| bc.last_ban),
        Some(1_000)
    );
    assert_eq!(state.ban_counts.get(&ipv6).map(|bc| bc.count), Some(1));
    assert_eq!(
        state.ban_counts.get(&ipv6).map(|bc| bc.last_ban),
        Some(2_000)
    );
}

#[test]
fn delete_persists_across_reopen() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
    let key = (ip, "sshd".to_string());

    {
        let store = open(dir.path());
        store
            .write(|tx| {
                tx.bans.put(
                    key.clone(),
                    BanRecord {
                        ip,
                        jail_id: "sshd".to_string(),
                        banned_at: 0,
                        expires_at: Some(60),
                    },
                );
                Ok(())
            })
            .expect("write ban");
        store
            .write(|tx| {
                tx.bans.delete(&key);
                Ok(())
            })
            .expect("write delete");
    }

    let reopened = open(dir.path());
    assert!(
        reopened.read().bans.is_empty(),
        "a deleted ban must not reappear after reopen"
    );
}

#[test]
fn multiple_jails_for_same_ip_persist_independently() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ip = IpAddr::V4(Ipv4Addr::new(5, 5, 5, 5));

    {
        let store = open(dir.path());
        store
            .write(|tx| {
                tx.bans.put(
                    (ip, "sshd".to_string()),
                    BanRecord {
                        ip,
                        jail_id: "sshd".to_string(),
                        banned_at: 10,
                        expires_at: Some(70),
                    },
                );
                tx.bans.put(
                    (ip, "nginx".to_string()),
                    BanRecord {
                        ip,
                        jail_id: "nginx".to_string(),
                        banned_at: 20,
                        expires_at: Some(80),
                    },
                );
                Ok(())
            })
            .expect("write");
        // Unban only the sshd jail entry.
        store
            .write(|tx| {
                tx.bans.delete(&(ip, "sshd".to_string()));
                Ok(())
            })
            .expect("write delete");
    }

    let reopened = open(dir.path());
    let state = reopened.read();
    assert!(
        !state.bans.contains_key(&(ip, "sshd".to_string())),
        "sshd ban should have been deleted"
    );
    assert!(
        state.bans.contains_key(&(ip, "nginx".to_string())),
        "nginx ban for the same IP must survive an unrelated jail's unban"
    );
}

#[test]
fn empty_store_replays_to_default_state() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open(dir.path());
    let state = store.read();
    assert!(state.bans.is_empty());
    assert!(state.ban_counts.is_empty());
}

#[test]
fn corrupt_wal_tail_drops_only_the_torn_entry() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ip_a = IpAddr::V4(Ipv4Addr::new(9, 9, 9, 1));
    let ip_b = IpAddr::V4(Ipv4Addr::new(9, 9, 9, 2));

    {
        let store = open(dir.path());
        store
            .write(|tx| {
                tx.bans.put(
                    (ip_a, "sshd".to_string()),
                    BanRecord {
                        ip: ip_a,
                        jail_id: "sshd".to_string(),
                        banned_at: 1,
                        expires_at: Some(100),
                    },
                );
                Ok(())
            })
            .expect("write first entry");
        store
            .write(|tx| {
                tx.bans.put(
                    (ip_b, "sshd".to_string()),
                    BanRecord {
                        ip: ip_b,
                        jail_id: "sshd".to_string(),
                        banned_at: 2,
                        expires_at: Some(200),
                    },
                );
                Ok(())
            })
            .expect("write second entry");
    }

    // Simulate a torn write: flip the trailing bytes of the WAL file, which
    // land in the last-written entry (ip_b)'s CRC/payload.
    let wal_path = dir.path().join("wal.bin");
    let mut bytes = std::fs::read(&wal_path).expect("read wal.bin");
    let len = bytes.len();
    assert!(len >= 2, "wal should have content to corrupt");
    bytes[len - 1] ^= 0xFF;
    bytes[len - 2] ^= 0xFF;
    std::fs::write(&wal_path, &bytes).expect("write corrupted wal.bin");

    let reopened = open(dir.path());
    let state = reopened.read();
    assert!(
        state.bans.contains_key(&(ip_a, "sshd".to_string())),
        "the entry preceding the corruption must survive replay"
    );
    assert!(
        !state.bans.contains_key(&(ip_b, "sshd".to_string())),
        "a torn trailing entry must be dropped wholesale, not partially applied"
    );
}

#[test]
fn truncated_wal_file_does_not_error_on_open() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ip = IpAddr::V4(Ipv4Addr::new(7, 7, 7, 7));

    {
        let store = open(dir.path());
        store
            .write(|tx| {
                tx.bans.put(
                    (ip, "sshd".to_string()),
                    BanRecord {
                        ip,
                        jail_id: "sshd".to_string(),
                        banned_at: 1,
                        expires_at: Some(50),
                    },
                );
                Ok(())
            })
            .expect("write");
    }

    // Truncate the WAL file mid-entry to simulate a crash during append.
    let wal_path = dir.path().join("wal.bin");
    let len = std::fs::metadata(&wal_path).expect("stat wal.bin").len();
    assert!(len > 4, "wal should have enough content to truncate");
    let truncated_len = len / 2;
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(&wal_path)
        .expect("open wal.bin for truncation");
    file.set_len(truncated_len).expect("truncate wal.bin");
    drop(file);

    // Must not panic or error — a truncated tail is treated as corruption
    // and the store falls back to whatever state replayed cleanly.
    let store = Store::<BanState, WalBackend<BanState>>::open_wal(dir.path().to_path_buf())
        .expect("open must recover gracefully from a truncated WAL");
    let state = store.read();
    assert!(
        state.bans.len() <= 1,
        "truncated WAL must not fabricate entries: {:?}",
        state.bans
    );
}

// ---------------------------------------------------------------------------
// Schema versioning / migration
// ---------------------------------------------------------------------------

/// A local duplicate of the OLD `BanState` layout: `ban_counts` held a bare
/// `u32` and there was no `meta` (schema-version) collection.
#[derive(Debug, Clone, Default, Serialize, Deserialize, Replayable, Transactable)]
struct OldBanState {
    #[etch(collection = 0)]
    bans: HashMap<(IpAddr, String), BanRecord>,
    #[etch(collection = 1)]
    ban_counts: HashMap<IpAddr, u32>,
}

#[test]
fn fresh_store_is_stamped_and_reopens_cleanly() {
    let dir = tempfile::tempdir().expect("tempdir");

    // First open stamps the schema version into an empty store.
    {
        let store = open_ban_store(dir.path().to_path_buf()).expect("fresh open");
        assert_eq!(
            store.read().meta.get("schema_version").copied(),
            Some(SCHEMA_VERSION),
            "a fresh store must be stamped with the current schema version"
        );
    }

    // Reopening a store the new code wrote must succeed (version matches).
    let reopened = open_ban_store(dir.path().to_path_buf()).expect("reopen same-version store");
    assert_eq!(
        reopened.read().meta.get("schema_version").copied(),
        Some(SCHEMA_VERSION)
    );
}

#[test]
fn opening_old_format_wal_is_a_clean_schema_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));

    // Persist a store in the OLD layout: a ban plus a bare-u32 ban_count, no
    // meta collection — exactly what a pre-migration daemon left on disk.
    {
        let old = Store::<OldBanState, WalBackend<OldBanState>>::open_wal(dir.path().to_path_buf())
            .expect("open old-layout store");
        old.write(|tx| {
            tx.bans.put(
                (ip, "sshd".to_string()),
                BanRecord {
                    ip,
                    jail_id: "sshd".to_string(),
                    banned_at: 100,
                    expires_at: Some(700),
                },
            );
            tx.ban_counts.put(ip, 5);
            Ok(())
        })
        .expect("write old state");
    }

    // Opening with the NEW type must fail with a clean SchemaMismatch (not a
    // silent misread) — the meta version is absent while data is present. This
    // is what the server's migration path turns into "preserved at .bak".
    match open_ban_store(dir.path().to_path_buf()) {
        Err(crate::error::Error::SchemaMismatch { .. }) => {}
        Err(other) => panic!("expected SchemaMismatch, got: {other:?}"),
        Ok(_) => panic!("opening an old-format WAL must be a clean error, not a silent misread"),
    }
}

#[test]
fn version_mismatch_is_a_clean_schema_error() {
    let dir = tempfile::tempdir().expect("tempdir");

    // Stamp a future/incompatible schema version directly.
    {
        let store = open(dir.path());
        store
            .write(|tx| {
                tx.meta
                    .put("schema_version".to_string(), SCHEMA_VERSION + 1);
                Ok(())
            })
            .expect("write future version");
    }

    match open_ban_store(dir.path().to_path_buf()) {
        Err(crate::error::Error::SchemaMismatch { .. }) => {}
        Err(other) => panic!("expected SchemaMismatch, got: {other:?}"),
        Ok(_) => panic!("a future schema version must be rejected"),
    }
}
