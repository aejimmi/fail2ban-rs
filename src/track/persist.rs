//! Etch-backed persistent ban state.
//!
//! Three collections: active bans keyed by (ip, jail), per-IP ban counts for
//! ban-time escalation (each carrying its last-ban timestamp so counts can
//! decay), and a small metadata map holding the on-disk schema version.

use std::collections::HashMap;
use std::net::IpAddr;

use etchdb::{Replayable, Store, Transactable, WalBackend};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::track::state::BanRecord;

/// On-disk schema version for [`BanState`].
///
/// Bumped whenever a collection's value layout changes incompatibly. A store
/// whose persisted version differs (or is absent while data exists) is treated
/// as an incompatible legacy format and migrated aside rather than misread.
pub const SCHEMA_VERSION: u64 = 1;

/// Metadata key under which the schema version is persisted.
const SCHEMA_VERSION_KEY: &str = "schema_version";

/// Per-IP escalation counter plus the timestamp of the most recent ban.
///
/// The `last_ban` timestamp lets the sweep expire stale counters so escalation
/// state cannot grow without bound; see the tracker sweep for decay handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BanCount {
    /// Number of times this IP has been banned (drives ban-time escalation).
    pub count: u32,
    /// Unix timestamp of the most recent ban that updated this counter.
    pub last_ban: i64,
}

/// Persistent ban state backed by etch WAL.
#[derive(Debug, Clone, Default, Serialize, Deserialize, Replayable, Transactable)]
pub struct BanState {
    /// Active bans keyed by `(ip, jail)`.
    #[etch(collection = 0)]
    pub bans: HashMap<(IpAddr, String), BanRecord>,
    /// Per-IP escalation counters keyed by IP.
    #[etch(collection = 1)]
    pub ban_counts: HashMap<IpAddr, BanCount>,
    /// Store metadata (schema version, etc.) keyed by a short string.
    #[etch(collection = 2)]
    pub meta: HashMap<String, u64>,
}

/// Open the WAL-backed ban store, verifying (or stamping) the schema version.
///
/// A fresh store is stamped with [`SCHEMA_VERSION`]. An existing store whose
/// version matches loads normally. Any other case — a version mismatch, or data
/// present with no version (an incompatible legacy WAL) — returns
/// [`crate::error::Error::SchemaMismatch`] so the caller can migrate the store
/// directory aside instead of silently misreading old bytes.
pub fn open_ban_store(
    dir: std::path::PathBuf,
) -> crate::error::Result<Store<BanState, WalBackend<BanState>>> {
    let store = Store::<BanState, WalBackend<BanState>>::open_wal(dir)
        .map_err(|e| crate::error::Error::persistence(format!("opening ban store WAL: {e}")))?;
    // Surface any WAL entries the replay skipped or quarantined. etch loads
    // leniently (recover the valid prefix rather than refuse to start), but a
    // silent partial load is exactly what we don't want for ban state — log it.
    let report = store.replay_report();
    if report.has_loss() {
        warn!(phase = "startup", summary = %report.summary(), "ban store replay dropped entries");
    }
    verify_or_stamp_schema(&store)?;
    Ok(store)
}

/// Check the persisted schema version, stamping fresh stores and rejecting
/// incompatible ones.
fn verify_or_stamp_schema(
    store: &Store<BanState, WalBackend<BanState>>,
) -> crate::error::Result<()> {
    let (version, has_data) = {
        let state = store.read();
        let has_data = !state.bans.is_empty() || !state.ban_counts.is_empty();
        (state.meta.get(SCHEMA_VERSION_KEY).copied(), has_data)
    };
    match version {
        Some(v) if v == SCHEMA_VERSION => Ok(()),
        Some(v) => Err(crate::error::Error::schema_mismatch(format!(
            "persisted schema version {v} != supported {SCHEMA_VERSION}"
        ))),
        None if has_data => Err(crate::error::Error::schema_mismatch(
            "persisted state predates schema versioning (incompatible legacy WAL)",
        )),
        None => stamp_schema_version(store),
    }
}

/// Persist the current [`SCHEMA_VERSION`] into a fresh (empty) store.
fn stamp_schema_version(store: &Store<BanState, WalBackend<BanState>>) -> crate::error::Result<()> {
    store
        .write(|tx| {
            tx.meta
                .put(SCHEMA_VERSION_KEY.to_string(), SCHEMA_VERSION)?;
            Ok(())
        })
        .map_err(|e| crate::error::Error::persistence(format!("stamping schema version: {e}")))
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::indexing_slicing)]
#[path = "persist_test.rs"]
mod persist_test;
