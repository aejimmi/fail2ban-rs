//! Fault-injection fixtures for the tracker persistence tests.
//!
//! [`FaultStore`] wraps a real WAL store whose writes can be made to fail on
//! demand without touching production code: the store's snapshot threshold is
//! lowered so every write triggers a compaction, and the (already open) state
//! directory is made read-only so the snapshot cannot be created. The failure
//! therefore originates from the real etch store, surfacing through the
//! tracker's own `store.write` calls.

use std::collections::{HashMap, HashSet, VecDeque};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;

use etchdb::{Store, WalBackend};
use tempfile::TempDir;
use tokio::sync::mpsc;

use crate::enforce::FirewallCmd;
use crate::track::ban_calc::build_jail_params;
use crate::track::manual::ManualBanOutcome;
use crate::track::persist::BanState;
use crate::track::test_support::test_jail_config;
use crate::track::tracker_state::{BanIndex, Counters, PendingManualBans, TrackerState};
use crate::track::unban::UnbanOutcome;

/// Shared handle type of the tracker's ban store.
pub(crate) type BanStore = Arc<Store<BanState, WalBackend<BanState>>>;

/// A real WAL store in a temp dir whose writes can be forced to fail.
pub(crate) struct FaultStore {
    dir: TempDir,
    store: BanStore,
}

impl FaultStore {
    /// Open a healthy store.
    pub(crate) fn open() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store =
            Store::<BanState, WalBackend<BanState>>::open_wal(dir.path().to_path_buf()).unwrap();
        Self {
            dir,
            store: Arc::new(store),
        }
    }

    /// A shared handle to the store.
    pub(crate) fn store(&self) -> BanStore {
        Arc::clone(&self.store)
    }

    /// Make subsequent writes fail. Returns `false` (fault not injected, store
    /// healed) when the process can write into a read-only directory, i.e. it
    /// runs as root, in which case callers must skip.
    pub(crate) fn inject(&self) -> bool {
        self.store.set_snapshot_threshold(1);
        set_mode(self.dir.path(), 0o555);
        let probe = self.dir.path().join(".probe");
        if std::fs::File::create(&probe).is_err() {
            return true;
        }
        std::fs::remove_file(&probe).unwrap();
        self.heal();
        false
    }

    /// Undo [`inject`](Self::inject): writes succeed again.
    pub(crate) fn heal(&self) {
        set_mode(self.dir.path(), 0o755);
        self.store.set_snapshot_threshold(1000);
    }
}

impl Drop for FaultStore {
    fn drop(&mut self) {
        // Let TempDir remove the directory.
        set_mode(self.dir.path(), 0o755);
    }
}

fn set_mode(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// A tracker state plus the receiving ends of every channel it sends on.
pub(crate) struct Rig {
    pub(crate) state: TrackerState,
    pub(crate) executor_rx: mpsc::Receiver<FirewallCmd>,
    pub(crate) unban_rx: mpsc::Receiver<UnbanOutcome>,
    pub(crate) _resolve_rx: mpsc::Receiver<ManualBanOutcome>,
}

/// Build a tracker state over `store` with one `sshd` jail (`max_retry = 2`).
pub(crate) fn rig(store: BanStore) -> Rig {
    let mut jail = test_jail_config();
    jail.max_retry = 2;
    let jails = HashMap::from([("sshd".to_string(), jail)]);
    let (executor_tx, executor_rx) = mpsc::channel(32);
    let (resolve_tx, resolve_rx) = mpsc::channel(32);
    let (unban_outcome_tx, unban_rx) = mpsc::channel(32);
    let state = TrackerState {
        jail_params: build_jail_params(&jails),
        failures: HashMap::new(),
        store,
        index: BanIndex::default(),
        counters: Counters::default(),
        started_at: chrono::Utc::now().timestamp(),
        ban_count_decay: 0,
        executor_tx,
        resolve_tx,
        pending_manual: PendingManualBans::default(),
        pending_unbans: HashSet::new(),
        unban_retry_after: HashMap::new(),
        unban_outcome_tx,
        reconcile_enabled: false,
        reconcile_queue: VecDeque::new(),
        logger: None,
        #[cfg(feature = "maxmind")]
        maxmind: crate::track::maxmind::MaxmindState::load(
            &crate::track::test_support::test_global_config(),
            &jails,
        ),
    };
    Rig {
        state,
        executor_rx,
        unban_rx,
        _resolve_rx: resolve_rx,
    }
}
