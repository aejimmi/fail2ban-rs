//! Config reload logic — firewall init/teardown, watcher lifecycle, ban
//! reapplication.

use std::collections::HashMap;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use crate::config::Config;
use crate::detect::date::DateParser;
use crate::detect::ignore::IgnoreList;
use crate::detect::matcher::JailMatcher;
use crate::detect::watcher::Failure;
use crate::enforce::FirewallCmd;
use crate::logging::Logger;
use crate::track::TrackerCmd;
use crate::track::state::BanRecord;

/// Shared mutable state needed during config reload.
pub(super) struct ReloadContext<'a> {
    pub(super) config_path: &'a std::path::Path,
    pub(super) executor_tx: &'a mpsc::Sender<FirewallCmd>,
    pub(super) config: &'a mut Config,
    pub(super) watcher_cancel: &'a mut CancellationToken,
    pub(super) failure_tx: &'a mpsc::Sender<Failure>,
    pub(super) logger: Option<&'a Logger>,
}

/// Pre-compiled watcher plan for a single jail.
pub(super) struct WatcherPlan {
    pub(super) name: String,
    pub(super) jail: crate::config::JailConfig,
    pub(super) matcher: JailMatcher,
    pub(super) date_parser: DateParser,
    pub(super) ignore_list: IgnoreList,
}

/// Build watcher plans for all enabled jails.
pub(super) fn build_watcher_plan(config: &Config) -> crate::error::Result<Vec<WatcherPlan>> {
    config
        .enabled_jails()
        .map(|(name, jail)| {
            let matcher = if jail.ignoreregex.is_empty() {
                JailMatcher::new(&jail.filter)?
            } else {
                JailMatcher::with_ignoreregex(&jail.filter, &jail.ignoreregex)?
            };
            let date_parser = DateParser::new(jail.date_format)?;
            let ignore_list = IgnoreList::new(&jail.ignoreip, jail.ignoreself)?;
            Ok(WatcherPlan {
                name: name.to_string(),
                jail: jail.clone(),
                matcher,
                date_parser,
                ignore_list,
            })
        })
        .collect()
}

/// Spawn watcher tasks for each plan under the given cancellation token.
pub(super) fn spawn_watchers(
    watcher_plan: Vec<WatcherPlan>,
    failure_tx: &mpsc::Sender<Failure>,
    cancel: &CancellationToken,
    phase: &'static str,
) {
    for plan in watcher_plan {
        let tx = failure_tx.clone();
        let cancel = cancel.child_token();

        if plan.jail.log_backend == crate::config::LogBackend::Systemd {
            let journalmatch = plan.jail.journalmatch.clone();
            tokio::spawn(async move {
                crate::detect::journal::run(
                    plan.name,
                    journalmatch,
                    plan.matcher,
                    plan.date_parser,
                    plan.ignore_list,
                    tx,
                    cancel,
                    phase,
                )
                .await;
            });
            continue;
        }

        let log_path = plan.jail.log_path.clone();
        tokio::spawn(async move {
            crate::detect::watcher::run(
                plan.name,
                log_path,
                plan.matcher,
                plan.date_parser,
                plan.ignore_list,
                tx,
                cancel,
                phase,
            )
            .await;
        });
    }
}

/// Reload the daemon configuration in place: apply a firewall *diff*, restart
/// watchers, and update the tracker.
///
/// The firewall lifecycle is diff-based so a reload is no longer a security
/// window: only added jails are initialized, only removed jails are torn down,
/// and unchanged jails' kernel state is left completely alone — previously a
/// full teardown/reapply left every banned IP briefly unblocked. Watchers keep
/// full-restart semantics since log readers are not a security window.
pub(super) async fn reload_config(
    config_path: &std::path::Path,
    executor_tx: &mpsc::Sender<FirewallCmd>,
    tracker_cmd_tx: &mpsc::Sender<TrackerCmd>,
    current_config: &mut Config,
    watcher_cancel: &mut CancellationToken,
    failure_tx: &mpsc::Sender<Failure>,
    logger: Option<&Logger>,
) -> crate::error::Result<()> {
    let new_config = Config::from_file(config_path)?;
    let new_watcher_plan = build_watcher_plan(&new_config)?;
    let active_bans = query_active_bans(tracker_cmd_tx).await?;

    let delta = FirewallDelta::compute(current_config, &new_config);
    apply_firewall_delta(executor_tx, &delta, &new_config, &active_bans).await?;

    // Cancel old watchers only after the new config is known-good.
    watcher_cancel.cancel();
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let new_cancel = CancellationToken::new();
    spawn_watchers(new_watcher_plan, failure_tx, &new_cancel, "reload");
    *watcher_cancel = new_cancel;

    // Update tracker jail configs.
    let jail_configs: HashMap<String, _> = new_config
        .jail
        .iter()
        .filter(|(_, j)| j.enabled)
        .map(|(name, cfg)| (name.clone(), cfg.clone()))
        .collect();
    let jail_count = jail_configs.len();

    let _ = tracker_cmd_tx
        .send(TrackerCmd::UpdateConfig {
            global: new_config.global.clone(),
            jails: jail_configs,
        })
        .await;

    if let Some(t) = logger {
        t.log_reload(jail_count);
    }

    *current_config = new_config;

    Ok(())
}

/// The firewall lifecycle actions a reload must perform, computed by diffing
/// the old and new enabled-jail sets.
///
/// The delta key is *jail name plus backend config*: a jail present in both
/// configs with the same backend is `kept` (its kernel state is never touched);
/// a jail whose backend changed is treated as `removed` **and** `added` so the
/// executor rebuilds its backend.
pub(super) struct FirewallDelta {
    /// Jails to register + initialize (newly enabled or backend-type changed).
    pub(super) added: Vec<String>,
    /// Jails to tear down + deregister (disabled/deleted or backend changed).
    pub(super) removed: Vec<String>,
    /// Jails whose firewall state is left completely untouched.
    pub(super) kept: Vec<String>,
}

impl FirewallDelta {
    /// Diff the enabled jails of `old` and `new` into add/remove/keep buckets.
    pub(super) fn compute(old: &Config, new: &Config) -> Self {
        let old_jails: HashMap<&str, &crate::config::JailConfig> = old.enabled_jails().collect();
        let new_jails: HashMap<&str, &crate::config::JailConfig> = new.enabled_jails().collect();

        let mut delta = Self {
            added: Vec::new(),
            removed: Vec::new(),
            kept: Vec::new(),
        };
        for (&name, &new_cfg) in &new_jails {
            delta.classify_new(name, new_cfg, &old_jails);
        }
        for &name in old_jails.keys() {
            if !new_jails.contains_key(name) {
                delta.removed.push(name.to_string());
            }
        }
        delta
    }

    /// Bucket a jail that is enabled in the new config.
    fn classify_new(
        &mut self,
        name: &str,
        new_cfg: &crate::config::JailConfig,
        old_jails: &HashMap<&str, &crate::config::JailConfig>,
    ) {
        match old_jails.get(name) {
            None => self.added.push(name.to_string()),
            Some(old_cfg) if backend_differs(&old_cfg.backend, &new_cfg.backend) => {
                self.removed.push(name.to_string());
                self.added.push(name.to_string());
            }
            Some(_) => self.kept.push(name.to_string()),
        }
    }
}

/// Whether two backend configs differ enough to require a rebuild.
///
/// Any type change (e.g. nftables → iptables/script) differs; two scripts
/// differ only if their ban/unban commands changed. Identical backends are
/// left untouched so the jail counts as `kept`.
fn backend_differs(a: &crate::config::Backend, b: &crate::config::Backend) -> bool {
    use crate::config::Backend;
    match (a, b) {
        (Backend::Nftables, Backend::Nftables) | (Backend::Iptables, Backend::Iptables) => false,
        (
            Backend::Script {
                ban_cmd: a_ban,
                unban_cmd: a_unban,
            },
            Backend::Script {
                ban_cmd: b_ban,
                unban_cmd: b_unban,
            },
        ) => a_ban != b_ban || a_unban != b_unban,
        _ => true,
    }
}

/// Apply a firewall delta in place: remove dropped jails, add new ones and
/// reapply only their stored bans, and leave unchanged jails alone.
///
/// Removed jails are processed before added ones so a backend-type change
/// (removed **and** added) tears the old state down before building the new.
pub(super) async fn apply_firewall_delta(
    executor_tx: &mpsc::Sender<FirewallCmd>,
    delta: &FirewallDelta,
    new_config: &Config,
    active_bans: &[BanRecord],
) -> crate::error::Result<()> {
    for name in &delta.kept {
        info!(phase = "reload", jail = %name, action = "kept", "firewall state left untouched");
    }
    for name in &delta.removed {
        send_remove_jail(executor_tx, name).await;
    }
    for name in &delta.added {
        let Some(jail) = new_config.jail.get(name) else {
            continue;
        };
        send_add_jail(executor_tx, name, jail).await?;
    }
    let added: std::collections::HashSet<&str> = delta.added.iter().map(String::as_str).collect();
    reapply_added_bans(executor_tx, active_bans, &added).await
}

/// Register + initialize one added jail's firewall, waiting for the ack.
async fn send_add_jail(
    executor_tx: &mpsc::Sender<FirewallCmd>,
    name: &str,
    jail: &crate::config::JailConfig,
) -> crate::error::Result<()> {
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    let cmd = FirewallCmd::AddJail {
        jail_id: name.to_string(),
        backend: jail.backend.clone(),
        ports: jail.port.clone(),
        protocol: jail.protocol.clone(),
        done: done_tx,
    };
    if executor_tx.send(cmd).await.is_err() {
        return Err(crate::error::Error::ChannelClosed);
    }
    match done_rx.await {
        Ok(Ok(())) => {
            info!(phase = "reload", jail = %name, action = "added", "firewall jail added");
            Ok(())
        }
        Ok(Err(e)) => {
            error!(phase = "reload", jail = %name, error = %e, "firewall jail add failed");
            Err(e)
        }
        Err(_) => Err(crate::error::Error::ChannelClosed),
    }
}

/// Tear down + deregister one removed jail's firewall (best-effort).
async fn send_remove_jail(executor_tx: &mpsc::Sender<FirewallCmd>, name: &str) {
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    let cmd = FirewallCmd::RemoveJail {
        jail_id: name.to_string(),
        done: done_tx,
    };
    if executor_tx.send(cmd).await.is_err() {
        return;
    }
    match done_rx.await {
        Ok(Ok(())) => {
            info!(phase = "reload", jail = %name, action = "removed", "firewall jail removed");
        }
        Ok(Err(e)) => {
            tracing::warn!(phase = "reload", jail = %name, error = %e, "firewall jail remove failed");
        }
        Err(_) => {}
    }
}

/// Reapply stored bans belonging to freshly added jails — and only those.
///
/// Kept jails' bans are already live in the kernel and must not be re-issued;
/// removed jails' bans were dropped by their teardown.
async fn reapply_added_bans(
    executor_tx: &mpsc::Sender<FirewallCmd>,
    active_bans: &[BanRecord],
    added: &std::collections::HashSet<&str>,
) -> crate::error::Result<()> {
    for ban in active_bans {
        if added.contains(ban.jail_id.as_str()) {
            send_ban(executor_tx, ban).await?;
        }
    }
    Ok(())
}

/// Send a single `Ban` command and wait for the executor's ack.
async fn send_ban(
    executor_tx: &mpsc::Sender<FirewallCmd>,
    ban: &BanRecord,
) -> crate::error::Result<()> {
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    let cmd = FirewallCmd::Ban {
        ip: ban.ip,
        jail_id: ban.jail_id.clone(),
        banned_at: ban.banned_at,
        expires_at: ban.expires_at,
        done: Some(done_tx),
    };
    executor_tx
        .send(cmd)
        .await
        .map_err(|_| crate::error::Error::ChannelClosed)?;
    match done_rx.await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(crate::error::Error::ChannelClosed),
    }
}

/// Send `TeardownJailFull` commands for each jail name (daemon shutdown).
///
/// Unlike a reload's per-jail [`send_remove_jail`], this asks each backend to
/// remove any shared infrastructure it owns (e.g. the nftables table) so
/// nothing leaks on exit.
pub(super) async fn teardown_firewalls_full<'a>(
    executor_tx: &mpsc::Sender<FirewallCmd>,
    jail_names: impl Iterator<Item = &'a str>,
    phase: &'static str,
) {
    for name in jail_names {
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let cmd = FirewallCmd::TeardownJailFull {
            jail_id: name.to_string(),
            done: done_tx,
        };
        if executor_tx.send(cmd).await.is_err() {
            break;
        }
        match done_rx.await {
            Ok(Ok(())) => info!(phase, jail = %name, "firewall fully torn down"),
            Ok(Err(e)) => {
                tracing::warn!(phase, jail = %name, error = %e, "firewall full teardown failed");
            }
            Err(_) => break,
        }
    }
}

/// Query the tracker for all currently active bans.
pub(super) async fn query_active_bans(
    tracker_cmd_tx: &mpsc::Sender<TrackerCmd>,
) -> crate::error::Result<Vec<BanRecord>> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    tracker_cmd_tx
        .send(TrackerCmd::QueryBans { respond: tx })
        .await
        .map_err(|_| crate::error::Error::ChannelClosed)?;
    rx.await.map_err(|_| crate::error::Error::ChannelClosed)
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
