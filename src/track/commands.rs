//! Command handling — query/mutate tracker state on behalf of the server.

use std::collections::HashMap;
use std::net::IpAddr;

use tracing::{debug, info, warn};

use crate::enforce::FirewallCmd;
use crate::track::ban_calc::build_jail_params;
use crate::track::execute::{RollbackReason, execute_unban, rollback_ban};
use crate::track::manual::{reply, start_manual_ban};
use crate::track::sweep::request_jail_reconcile;
use crate::track::tracker_state::TrackerState;
use crate::track::{FirewallCmdBuilder, JailStats, Stats, TrackerCmd};

/// Dispatch a single [`TrackerCmd`] against the tracker state.
///
/// Never awaits a firewall acknowledgement: manual bans hand their ack wait to
/// a spawned task (see [`start_manual_ban`]) so a hung firewall command cannot
/// stall failure processing, sweeps, or other control commands.
pub(super) async fn handle_cmd(cmd: TrackerCmd, s: &mut TrackerState) {
    match cmd {
        TrackerCmd::QueryBans { respond } => {
            reply(respond, s.store.read().bans.values().cloned().collect());
        }
        TrackerCmd::ManualBan {
            ip,
            jail_id,
            ban_time,
            respond,
        } => start_manual_ban(ip, jail_id, ban_time, respond, s).await,
        TrackerCmd::ManualUnban {
            ip,
            jail_id,
            respond,
        } => reply(respond, do_manual_unban(ip, &jail_id, s).await),
        TrackerCmd::BanApplyFailed {
            ip,
            jail_id,
            banned_at,
        } => rollback_failed_ban(ip, &jail_id, banned_at, s).await,
        TrackerCmd::ForwardFirewall { jail_id, build } => {
            forward_firewall(&jail_id, build, s).await;
        }
        TrackerCmd::GetStats { respond } => reply(respond, build_stats(s)),
        TrackerCmd::UpdateConfig {
            global,
            jails,
            respond,
        } => {
            apply_config_update(s, &global, &jails);
            reply(respond, ());
        }
        TrackerCmd::ReconcileJail { jail_id } => request_jail_reconcile(&jail_id, s),
    }
}

/// Roll back a ban the executor failed to apply — but only if the current
/// record is the ban that failed (same `banned_at`); a stale notice for an
/// earlier ban of the same key must not remove a newer one.
///
/// After rolling back, an `Unban` is enqueued: a `ReplaceJail`/`AddJail` or
/// `Reconcile` batch forwarded before this notice arrived may have re-applied
/// the IP to the kernel, and dropping the record without an `Unban` would
/// orphan that entry. Backends tolerate unbanning an absent entry.
async fn rollback_failed_ban(ip: IpAddr, jail_id: &str, banned_at: i64, s: &mut TrackerState) {
    let key = (ip, jail_id.to_string());
    let current = s.store.read().bans.get(&key).map(|b| b.banned_at);
    if current != Some(banned_at) {
        debug!(%ip, jail = %jail_id, banned_at, ?current, "stale ban-failure notice ignored");
        return;
    }
    rollback_ban(ip, jail_id, RollbackReason::FirewallBanFailed, s);
    let cmd = FirewallCmd::Unban {
        ip,
        jail_id: jail_id.to_string(),
    };
    if s.executor_tx.send(cmd).await.is_err() {
        warn!(%ip, jail = %jail_id, "executor channel closed; rollback unban dropped");
    }
}

/// Build a firewall command from the jail's current bans and enqueue it
/// behind every `Ban`/`Unban` the tracker has already sent.
async fn forward_firewall(jail_id: &str, build: FirewallCmdBuilder, s: &TrackerState) {
    let bans: Vec<_> = s
        .store
        .read()
        .bans
        .values()
        .filter(|b| b.jail_id == jail_id)
        .cloned()
        .collect();
    debug!(jail = %jail_id, bans = bans.len(), "forwarding firewall command");
    if s.executor_tx.send(build(bans)).await.is_err() {
        warn!(jail = %jail_id, "executor channel closed; firewall command dropped");
    }
}

/// Build a runtime statistics snapshot from the current state.
fn build_stats(s: &TrackerState) -> Stats {
    let now = chrono::Utc::now().timestamp();
    let store_state = s.store.read();
    let mut jail_stats: HashMap<String, JailStats> = HashMap::new();
    for jail_id in s.jail_params.keys() {
        let active = store_state
            .bans
            .values()
            .filter(|b| b.jail_id == *jail_id)
            .count();
        jail_stats.insert(
            jail_id.clone(),
            JailStats {
                active_bans: active,
                total_bans: *s.counters.jail_bans.get(jail_id).unwrap_or(&0),
                total_failures: *s.counters.jail_failures.get(jail_id).unwrap_or(&0),
            },
        );
    }
    Stats {
        uptime_secs: (now - s.started_at).max(0),
        active_bans: store_state.bans.len(),
        total_bans: s.counters.total_bans,
        total_unbans: s.counters.total_unbans,
        total_failures: s.counters.total_failures,
        jails: jail_stats,
    }
}

/// Hot-reload the global and jail configurations.
fn apply_config_update(
    s: &mut TrackerState,
    global: &crate::config::GlobalConfig,
    jails: &HashMap<String, crate::config::JailConfig>,
) {
    info!(
        phase = "reload",
        jails = jails.len(),
        "updating configurations"
    );
    let new_params = build_jail_params(jails);
    s.failures
        .retain(|(_, jail_id), _| new_params.contains_key(jail_id));
    s.jail_params = new_params;
    s.ban_count_decay = global.ban_count_decay;
    #[cfg(feature = "maxmind")]
    s.maxmind.reload(global, jails);
}

/// Manually unban an IP, rejecting unknown jails and IPs that are not banned.
async fn do_manual_unban(
    ip: IpAddr,
    jail_id: &str,
    s: &mut TrackerState,
) -> crate::error::Result<()> {
    if !s.jail_params.contains_key(jail_id) {
        return Err(crate::error::Error::config(format!(
            "unknown jail: {jail_id}"
        )));
    }
    let key = (ip, jail_id.to_string());
    if !s.index.banned_keys.contains(&key) {
        return Err(crate::error::Error::NotBanned {
            ip,
            jail: jail_id.to_string(),
        });
    }
    if let Err(e) = s.store.write(|tx| {
        tx.bans.delete(&key);
        Ok(())
    }) {
        warn!(error = %e, "state persist failed: {e}");
    }
    info!(
        %ip,
        jail = %jail_id,
        reason = "manual",
        "unbanned"
    );
    execute_unban(ip, jail_id, true, s).await;
    Ok(())
}
