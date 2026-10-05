//! Periodic reconcile: verify active bans against kernel state and re-apply
//! any the firewall is missing.
//!
//! Bans are grouped per jail so each jail's backend is queried once via
//! [`FirewallBackend::snapshot`] where supported, falling back to per-IP
//! [`FirewallBackend::is_banned`] checks otherwise. Backends that cannot
//! verify state at all ([`FirewallBackend::can_verify`] is `false`, e.g. the
//! script backend) are skipped so their ban command is never re-run.

use std::collections::{HashMap, HashSet};
use std::hash::BuildHasher;
use std::net::IpAddr;

use tracing::{debug, info, warn};

use crate::enforce::FirewallBackend;
use crate::error::{Error, Result};
use crate::track::state::BanRecord;

/// Verify each ban against the firewall and re-apply any the kernel is missing.
pub(super) async fn reconcile_bans<S: BuildHasher>(
    backends: &HashMap<String, Box<dyn FirewallBackend>, S>,
    bans: Vec<BanRecord>,
) {
    let now = chrono::Utc::now().timestamp();
    let mut reapplied = 0usize;
    for (jail, group) in group_by_jail(&bans) {
        reapplied += reconcile_jail(backends, jail, &group, now).await;
    }
    if reapplied > 0 {
        info!(
            reapplied,
            checked = bans.len(),
            "reconcile re-applied missing bans"
        );
    } else {
        debug!(checked = bans.len(), "reconcile: no bans re-applied");
    }
}

/// Group bans by jail, preserving first-seen jail order and per-jail ban order.
fn group_by_jail(bans: &[BanRecord]) -> Vec<(&str, Vec<&BanRecord>)> {
    let mut index: HashMap<&str, usize> = HashMap::new();
    let mut groups: Vec<(&str, Vec<&BanRecord>)> = Vec::new();
    for ban in bans {
        let jail = ban.jail_id.as_str();
        let slot = *index.entry(jail).or_insert_with(|| {
            groups.push((jail, Vec::new()));
            groups.len() - 1
        });
        if let Some((_, group)) = groups.get_mut(slot) {
            group.push(ban);
        }
    }
    groups
}

/// Reconcile one jail's bans; returns how many were re-applied.
async fn reconcile_jail<S: BuildHasher>(
    backends: &HashMap<String, Box<dyn FirewallBackend>, S>,
    jail: &str,
    group: &[&BanRecord],
    now: i64,
) -> usize {
    let Some(backend) = backends.get(jail) else {
        warn!(
            jail = %jail,
            count = group.len(),
            reason = "no_backend",
            "reconcile skipped; jail has no registered backend"
        );
        return 0;
    };
    let backend = backend.as_ref();
    if !backend.can_verify() {
        debug!(
            jail = %jail,
            backend = backend.name(),
            count = group.len(),
            "reconcile skipped; backend cannot verify firewall state"
        );
        return 0;
    }
    let snapshot = match load_snapshot(backend, jail).await {
        Ok(snapshot) => snapshot,
        Err(e) => {
            warn!(jail, error = %e, "reconcile skipped; firewall listing exceeds output limit");
            return 0;
        }
    };
    let mut reapplied = 0usize;
    for ban in group {
        if is_missing(backend, ban, snapshot.as_ref()).await && reapply(backend, ban, now).await {
            reapplied += 1;
        }
    }
    reapplied
}

/// Fetch a jail's banned-IP snapshot. `None` means "check per IP" — either
/// the backend does not support snapshots or the query failed. An output-limit
/// failure stops this jail: per-IP fallback can repeat the same oversized listing.
async fn load_snapshot(
    backend: &dyn FirewallBackend,
    jail: &str,
) -> Result<Option<HashSet<IpAddr>>> {
    match backend.snapshot(jail).await {
        Ok(snapshot) => Ok(snapshot),
        Err(e @ Error::FirewallOutputLimit { .. }) => Err(e),
        Err(e) => {
            warn!(
                jail = %jail,
                error = %e,
                "reconcile snapshot failed; falling back to per-IP checks"
            );
            Ok(None)
        }
    }
}

/// Whether `ban` is absent from the firewall. A failed per-IP check is
/// treated as "present" so a flaky query does not trigger a re-ban storm.
async fn is_missing(
    backend: &dyn FirewallBackend,
    ban: &BanRecord,
    snapshot: Option<&HashSet<IpAddr>>,
) -> bool {
    if let Some(set) = snapshot {
        return !set.contains(&ban.ip);
    }
    match backend.is_banned(&ban.ip, &ban.jail_id).await {
        Ok(present) => !present,
        Err(e) => {
            warn!(ip = %ban.ip, jail = %ban.jail_id, error = %e, "reconcile is_banned check failed");
            false
        }
    }
}

/// Re-apply a missing ban; returns `true` on success.
async fn reapply(backend: &dyn FirewallBackend, ban: &BanRecord, now: i64) -> bool {
    match backend
        .ban_with_timeout(&ban.ip, &ban.jail_id, ban.expires_at, now)
        .await
    {
        Ok(()) => {
            info!(ip = %ban.ip, jail = %ban.jail_id, "reconcile re-applied missing ban");
            true
        }
        Err(e) => {
            warn!(ip = %ban.ip, jail = %ban.jail_id, error = %e, "reconcile re-ban failed");
            false
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::needless_pass_by_value
)]
#[path = "executor_reconcile_test.rs"]
mod executor_reconcile_test;
