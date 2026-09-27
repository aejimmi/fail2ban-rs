//! Config reload orchestration — watcher handoff, tracker update, and
//! daemon-shutdown teardown. The firewall diff/apply/rollback lives in
//! `reload_delta`; watcher spawning and stopping live in `watchers`.

use std::collections::HashMap;

use tokio::sync::{mpsc, oneshot};
use tracing::{info, warn};

use crate::config::Config;
use crate::detect::watcher::Failure;
use crate::enforce::FirewallCmd;
use crate::logging::Logger;
use crate::track::TrackerCmd;

use super::reload_delta::{FirewallDelta, apply_firewall_delta, send_and_ack};
use super::watchers::{WatcherPlan, Watchers, build_watcher_plan};

/// Shared mutable state needed during config reload.
pub(super) struct ReloadContext<'a> {
    pub(super) config_path: &'a std::path::Path,
    pub(super) executor_tx: &'a mpsc::Sender<FirewallCmd>,
    pub(super) config: &'a mut Config,
    pub(super) watchers: &'a mut Watchers,
    pub(super) failure_tx: &'a mpsc::Sender<Failure>,
    pub(super) logger: Option<&'a Logger>,
}

/// Reload the daemon configuration in place: apply a firewall *diff*, restart
/// watchers, and update the tracker.
///
/// The firewall lifecycle is diff-based so a reload is no longer a security
/// window: only added jails are initialized, only removed jails are torn down,
/// changed jails are replaced transactionally, and unchanged jails' kernel
/// state is left completely alone. Watchers keep full-restart semantics since
/// log readers are not a security window; the old watchers' positions are
/// handed to their replacements so no line is skipped or read twice.
///
/// Every fallible step (config parse, watcher plan, firewall delta) runs
/// before the old watchers are touched, so a failed reload leaves them
/// running.
pub(super) async fn reload_config(
    config_path: &std::path::Path,
    executor_tx: &mpsc::Sender<FirewallCmd>,
    tracker_cmd_tx: &mpsc::Sender<TrackerCmd>,
    current_config: &mut Config,
    watchers: &mut Watchers,
    failure_tx: &mpsc::Sender<Failure>,
    logger: Option<&Logger>,
) -> crate::error::Result<()> {
    let new_config = Config::from_file(config_path)?;
    let new_watcher_plan = build_watcher_plan(&new_config)?;

    let delta = FirewallDelta::compute(current_config, &new_config);
    let applied = apply_firewall_delta(
        executor_tx,
        tracker_cmd_tx,
        &delta,
        current_config,
        &new_config,
    )
    .await;
    // Whether the replacements committed or were rolled back, re-verify their
    // bans now rather than waiting for the periodic reconcile (a ban whose
    // apply failed on the replaced backend is healed this way).
    request_jail_reconciles(tracker_cmd_tx, delta.replacements()).await;
    applied?;

    let jail_count = update_tracker_config(tracker_cmd_tx, &new_config).await?;
    restart_watchers(new_watcher_plan, failure_tx, watchers).await;
    if let Some(t) = logger {
        t.log_reload(jail_count);
    }
    *current_config = new_config;
    Ok(())
}

/// Ask the tracker to reconcile each named jail against the firewall.
async fn request_jail_reconciles<'a>(
    tracker_cmd_tx: &mpsc::Sender<TrackerCmd>,
    jails: impl Iterator<Item = &'a str>,
) {
    for name in jails {
        let cmd = TrackerCmd::ReconcileJail {
            jail_id: name.to_string(),
        };
        if tracker_cmd_tx.send(cmd).await.is_err() {
            warn!(phase = "reload", jail = %name, "tracker gone; post-reload reconcile skipped");
            return;
        }
    }
}

/// Stop the old watchers (only once the new config is known-good), collect
/// where each stopped, and spawn the new ones resuming from those positions.
async fn restart_watchers(
    plan: Vec<WatcherPlan>,
    failure_tx: &mpsc::Sender<Failure>,
    watchers: &mut Watchers,
) {
    let resume = watchers.stop().await;
    *watchers = Watchers::spawn(plan, failure_tx, "reload", resume);
}

/// Send the reloaded enabled-jail configs to the tracker; returns the count.
async fn update_tracker_config(
    tracker_cmd_tx: &mpsc::Sender<TrackerCmd>,
    config: &Config,
) -> crate::error::Result<usize> {
    let jails: HashMap<String, _> = config
        .enabled_jails()
        .map(|(name, cfg)| (name.to_string(), cfg.clone()))
        .collect();
    let jail_count = jails.len();
    let (respond, ack) = oneshot::channel();
    let cmd = TrackerCmd::UpdateConfig {
        global: config.global.clone(),
        jails,
        respond,
    };
    tracker_cmd_tx
        .send(cmd)
        .await
        .map_err(|_| crate::error::Error::ChannelClosed)?;
    tokio::time::timeout(std::time::Duration::from_secs(10), ack)
        .await
        .map_err(|_| {
            crate::error::Error::firewall("tracker config update acknowledgement timed out")
        })?
        .map_err(|_| crate::error::Error::ChannelClosed)?;
    Ok(jail_count)
}

/// Send `TeardownJailFull` commands for each jail name (daemon shutdown).
///
/// Unlike a reload's per-jail removal, this asks each backend to remove any
/// shared infrastructure it owns (e.g. the nftables table) so nothing leaks
/// on exit. Stops early once the executor is gone.
pub(super) async fn teardown_firewalls_full<'a>(
    executor_tx: &mpsc::Sender<FirewallCmd>,
    jail_names: impl Iterator<Item = &'a str>,
    phase: &'static str,
) {
    for name in jail_names {
        let result = send_and_ack(executor_tx, |done| FirewallCmd::TeardownJailFull {
            jail_id: name.to_string(),
            done,
        })
        .await;
        match result {
            Ok(()) => info!(phase, jail = %name, "firewall fully torn down"),
            Err(crate::error::Error::ChannelClosed) => break,
            Err(e) => warn!(phase, jail = %name, error = %e, "firewall full teardown failed"),
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
#[path = "reload_test.rs"]
mod reload_test;
