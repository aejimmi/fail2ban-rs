//! Startup loading of persisted bans, pinned for expired records.

use super::*;

use std::net::Ipv4Addr;

use crate::track::persist::open_ban_store;

const EXPIRED_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 44));
const LIVE_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 45));

/// Persist one expired and one live ban, then close the store.
fn write_bans(dir: &Path) {
    let store = open_ban_store(dir.to_path_buf()).unwrap();
    let now = chrono::Utc::now().timestamp();
    let ban = |ip, expires_at| BanRecord {
        ip,
        jail_id: "sshd".to_string(),
        banned_at: now - 120,
        expires_at: Some(expires_at),
    };
    store
        .write(|tx| {
            tx.bans
                .put((EXPIRED_IP, "sshd".to_string()), ban(EXPIRED_IP, now - 60))?;
            tx.bans
                .put((LIVE_IP, "sshd".to_string()), ban(LIVE_IP, now + 600))?;
            Ok(())
        })
        .unwrap();
}

/// Pins current behaviour: an expired record is deleted from the store at
/// startup and is NOT handed to the executor or tracker, so no firewall
/// `Unban` is ever issued for it. Backends without a kernel-side timeout
/// (iptables, script) would keep such an address blocked with no record left
/// to retry; nftables/ipset elements carry their own timeout and self-clear.
#[tokio::test]
async fn test_open_state_purges_expired_ban_without_any_unban() {
    let dir = tempfile::tempdir().unwrap();
    write_bans(dir.path());

    let restored = open_state(dir.path()).await.unwrap();

    let restored_ips: Vec<IpAddr> = restored.bans.iter().map(|b| b.ip).collect();
    assert_eq!(restored_ips, vec![LIVE_IP], "expired ban not restored");
    let persisted = restored.store.read();
    assert!(
        !persisted
            .bans
            .contains_key(&(EXPIRED_IP, "sshd".to_string()))
    );
    assert!(persisted.bans.contains_key(&(LIVE_IP, "sshd".to_string())));
}
