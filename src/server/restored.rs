//! Startup ban-state loading: open the WAL store, purge expired bans, and
//! hand the survivors to the executor (restore) and tracker (seed).

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use etchdb::{FlushPolicy, Store, WalBackend};
use tracing::{info, warn};

use crate::track::persist::{BanCount, BanState};
use crate::track::state::BanRecord;

use super::startup::{handle_legacy_state, open_store_migrating};

/// Shared handle to the persistent ban store.
pub(super) type BanStore = Arc<Store<BanState, WalBackend<BanState>>>;

/// Persisted state recovered at startup.
pub(super) struct Restored {
    /// The opened store, shared with the tracker.
    pub(super) store: BanStore,
    /// Unexpired bans to re-apply.
    pub(super) bans: Vec<BanRecord>,
    /// Per-IP escalation counts.
    pub(super) ban_counts: HashMap<IpAddr, BanCount>,
}

/// Open the ban store (migrating legacy or incompatible state aside) and read
/// back every unexpired ban, purging expired ones from the WAL.
pub(super) async fn open_state(state_dir: &Path) -> crate::error::Result<Restored> {
    handle_legacy_state(state_dir).await?;
    let mut store = open_store_migrating(state_dir).await?;
    store.set_flush_policy(FlushPolicy::Grouped {
        interval: Duration::from_millis(100),
    });
    let store = Arc::new(store);
    let (bans, ban_counts) = load_restored(&store);
    Ok(Restored {
        store,
        bans,
        ban_counts,
    })
}

/// Split persisted bans into live ones (returned) and expired ones (purged).
fn load_restored(store: &BanStore) -> (Vec<BanRecord>, HashMap<IpAddr, BanCount>) {
    let now = chrono::Utc::now().timestamp();
    let (expired, bans, counts) = {
        let state = store.read();
        let expired: Vec<_> = state
            .bans
            .iter()
            .filter(|(_, ban)| ban.expires_at.is_some_and(|exp| exp <= now))
            .map(|(key, _)| key.clone())
            .collect();
        let bans: Vec<BanRecord> = state
            .bans
            .values()
            .filter(|ban| ban.expires_at.is_none_or(|exp| exp > now))
            .cloned()
            .collect();
        (expired, bans, state.ban_counts.clone())
    };
    purge_expired(store, &expired);
    if bans.is_empty() {
        info!(phase = "startup", "no persisted state found");
    } else {
        info!(
            phase = "startup",
            bans = bans.len(),
            "persisted state loaded"
        );
    }
    (bans, counts)
}

/// Delete expired ban keys from the store in one transaction.
fn purge_expired(store: &BanStore, keys: &[(IpAddr, String)]) {
    if keys.is_empty() {
        return;
    }
    info!(phase = "startup", bans = keys.len(), "expired bans purged");
    let result = store.write(|tx| {
        for key in keys {
            tx.bans.delete(key);
        }
        Ok(())
    });
    if let Err(e) = result {
        warn!(phase = "startup", error = %e, "expired ban purge failed");
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
#[path = "restored_test.rs"]
mod restored_test;
