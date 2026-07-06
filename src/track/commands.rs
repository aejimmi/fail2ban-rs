//! Command handling — query/mutate tracker state on behalf of the server.

use std::collections::HashMap;
use std::net::IpAddr;

use tracing::{info, warn};

use crate::track::ban_calc::build_jail_params;
use crate::track::execute::{execute_ban, execute_unban, rollback_ban};
use crate::track::state::BanRecord;
use crate::track::tracker_state::TrackerState;
use crate::track::{JailStats, Stats, TrackerCmd};

/// Dispatch a single [`TrackerCmd`] against the tracker state.
pub(super) async fn handle_cmd(cmd: TrackerCmd, s: &mut TrackerState) {
    match cmd {
        TrackerCmd::QueryBans { respond } => {
            let list: Vec<BanRecord> = s.store.read().bans.values().cloned().collect();
            let _ = respond.send(list);
        }

        TrackerCmd::ManualBan {
            ip,
            jail_id,
            ban_time,
            respond,
        } => {
            let result = do_manual_ban(ip, &jail_id, ban_time, s).await;
            let _ = respond.send(result);
        }

        TrackerCmd::ManualUnban {
            ip,
            jail_id,
            respond,
        } => {
            let result = do_manual_unban(ip, &jail_id, s).await;
            let _ = respond.send(result);
        }

        TrackerCmd::BanApplyFailed { ip, jail_id } => rollback_ban(ip, &jail_id, s),

        TrackerCmd::GetStats { respond } => {
            let _ = respond.send(build_stats(s));
        }

        TrackerCmd::UpdateConfig { global, jails } => apply_config_update(s, &global, &jails),
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

/// Manually ban an IP, rejecting unknown jails and already-banned IPs.
async fn do_manual_ban(
    ip: IpAddr,
    jail_id: &str,
    ban_time: i64,
    s: &mut TrackerState,
) -> crate::error::Result<()> {
    if !s.jail_params.contains_key(jail_id) {
        return Err(crate::error::Error::config(format!(
            "unknown jail: {jail_id}"
        )));
    }
    if s.index.banned_keys.contains(&(ip, jail_id.to_string())) {
        return Err(crate::error::Error::AlreadyBanned {
            ip,
            jail: jail_id.to_string(),
        });
    }
    info!(
        %ip,
        jail = %jail_id,
        ban_time,
        reason = "manual",
        "banned"
    );
    execute_ban(ip, jail_id, ban_time, true, None, s).await;
    Ok(())
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
