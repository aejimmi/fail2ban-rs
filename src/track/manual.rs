//! Manual (control-socket) bans.
//!
//! A manual ban must only report success once the firewall has applied it,
//! but a slow or hung firewall command must never stall the tracker loop. The
//! ban is therefore recorded as *pending*, the firewall ack is awaited on a
//! spawned waiter task (bounded by [`MANUAL_BAN_ACK_TIMEOUT`]), and the waiter
//! reports a [`ManualBanOutcome`] back to the tracker, which then commits
//! (notify) or rolls back the ban and answers the control request.

use std::net::IpAddr;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};

use crate::enforce::FirewallCmd;
use crate::error::{Error, Result};
use crate::track::execute::{RollbackReason, ban_cmd, record_ban, rollback_ban};
use crate::track::state::BanRecord;
use crate::track::tracker_state::TrackerState;

/// Upper bound on how long a manual ban waits for the firewall to apply it.
#[cfg(not(test))]
pub(super) const MANUAL_BAN_ACK_TIMEOUT: Duration = Duration::from_secs(60);
/// Shortened in unit tests so the hung-firewall timeout path runs quickly
/// (tokio's `test-util` clock control is not enabled for this crate).
#[cfg(test)]
pub(super) const MANUAL_BAN_ACK_TIMEOUT: Duration = Duration::from_secs(2);

/// A manual ban's firewall result, reported by its ack waiter to the tracker.
pub(super) struct ManualBanOutcome {
    /// Waiter id matching the tracker's pending entry.
    id: u64,
    ip: IpAddr,
    jail_id: String,
    ban_time: i64,
    /// Firewall result; errors carry the rollback reason.
    result: std::result::Result<(), (RollbackReason, Error)>,
    /// The control request's reply channel.
    respond: oneshot::Sender<Result<()>>,
}

/// Everything a spawned ack waiter needs.
struct AckWaiter {
    id: u64,
    ip: IpAddr,
    jail_id: String,
    ban_time: i64,
    respond: oneshot::Sender<Result<()>>,
    done_rx: oneshot::Receiver<Result<()>>,
    resolve_tx: mpsc::Sender<ManualBanOutcome>,
}

/// Start a manual ban: validate, record it as pending, dispatch the firewall
/// command, and hand the ack wait to a spawned task. Never awaits the ack.
pub(super) async fn start_manual_ban(
    ip: IpAddr,
    jail_id: String,
    ban_time: i64,
    respond: oneshot::Sender<Result<()>>,
    s: &mut TrackerState,
) {
    if let Err(e) = validate_manual_ban(ip, &jail_id, s) {
        reply(respond, Err(e));
        return;
    }
    let ban = match record_ban(ip, &jail_id, ban_time, None, s) {
        Ok(ban) => ban,
        Err(e) => {
            reply(respond, Err(e));
            return;
        }
    };
    let Some(done_rx) = dispatch_ban(&ban, s).await else {
        rollback_ban(ip, &jail_id, RollbackReason::ChannelClosed, s);
        reply(respond, Err(Error::ChannelClosed));
        return;
    };
    let id = s.pending_manual.insert((ip, jail_id.clone()));
    spawn_ack_waiter(AckWaiter {
        id,
        ip,
        jail_id,
        ban_time,
        respond,
        done_rx,
        resolve_tx: s.resolve_tx.clone(),
    });
}

/// Send the ban to the executor with an ack channel; `None` if the executor
/// is gone (the caller rolls the recorded ban back).
async fn dispatch_ban(ban: &BanRecord, s: &TrackerState) -> Option<oneshot::Receiver<Result<()>>> {
    let (done_tx, done_rx) = oneshot::channel();
    if s.executor_tx
        .send(ban_cmd(ban, Some(done_tx)))
        .await
        .is_err()
    {
        warn!(ip = %ban.ip, jail = %ban.jail_id, "executor channel closed");
        return None;
    }
    Some(done_rx)
}

/// Reject unknown jails and already-banned (or pending) IPs.
fn validate_manual_ban(ip: IpAddr, jail_id: &str, s: &TrackerState) -> Result<()> {
    if !s.jail_params.contains_key(jail_id) {
        return Err(Error::config(format!("unknown jail: {jail_id}")));
    }
    if s.index.banned_keys.contains(&(ip, jail_id.to_string())) {
        return Err(Error::AlreadyBanned {
            ip,
            jail: jail_id.to_string(),
        });
    }
    Ok(())
}

/// Await the firewall ack off the tracker loop and report the outcome back.
fn spawn_ack_waiter(w: AckWaiter) {
    tokio::spawn(async move {
        let result = await_ack(w.done_rx).await;
        let outcome = ManualBanOutcome {
            id: w.id,
            ip: w.ip,
            jail_id: w.jail_id,
            ban_time: w.ban_time,
            result,
            respond: w.respond,
        };
        if w.resolve_tx.send(outcome).await.is_err() {
            debug!("tracker stopped; manual ban outcome dropped");
        }
    });
}

/// Wait (bounded) for the executor's ack, classifying any failure.
async fn await_ack(
    done_rx: oneshot::Receiver<Result<()>>,
) -> std::result::Result<(), (RollbackReason, Error)> {
    match tokio::time::timeout(MANUAL_BAN_ACK_TIMEOUT, done_rx).await {
        Ok(Ok(Ok(()))) => Ok(()),
        Ok(Ok(Err(e))) => Err((RollbackReason::FirewallBanFailed, e)),
        Ok(Err(_)) => Err((RollbackReason::ChannelClosed, Error::ChannelClosed)),
        Err(_) => {
            let secs = MANUAL_BAN_ACK_TIMEOUT.as_secs();
            Err((
                RollbackReason::Timeout,
                Error::firewall(format!("firewall did not apply ban within {secs}s")),
            ))
        }
    }
}

/// Commit or roll back a manual ban once its ack waiter reports, then answer
/// the control request. A stale outcome (the ban was unbanned, expired, or
/// rolled back meanwhile) leaves tracker state and the firewall untouched.
pub(super) async fn handle_manual_ban_outcome(o: ManualBanOutcome, s: &mut TrackerState) {
    let current = s.pending_manual.resolve(&(o.ip, o.jail_id.clone()), o.id);
    let result = match o.result {
        Ok(()) => {
            if current {
                s.notify_ban(o.ip, &o.jail_id, o.ban_time, true);
                info!(ip = %o.ip, jail = %o.jail_id, ban_time = o.ban_time, reason = "manual", "banned");
            }
            Ok(())
        }
        Err((reason, e)) => {
            if current {
                if reason == RollbackReason::Timeout {
                    queue_timeout_unban(o.ip, &o.jail_id, s).await;
                }
                rollback_ban(o.ip, &o.jail_id, reason, s);
            }
            Err(e)
        }
    };
    reply(o.respond, result);
}

/// A timed-out ban command may still complete later, so queue an `Unban`
/// behind it — the executor processes commands in order, so a late-applied
/// ban cannot outlive its rolled-back record.
///
/// Only called while the pending entry is still current: once the IP was
/// unbanned (and possibly re-banned) the `Unban` would remove a newer ban.
async fn queue_timeout_unban(ip: IpAddr, jail_id: &str, s: &TrackerState) {
    let unban = FirewallCmd::Unban {
        ip,
        jail_id: jail_id.to_string(),
    };
    if s.executor_tx.send(unban).await.is_err() {
        debug!(%ip, jail = %jail_id, "executor gone; timeout unban not queued");
    }
}

/// Answer a control request, noting (not failing) a vanished requester.
pub(super) fn reply<T>(respond: oneshot::Sender<T>, value: T) {
    if respond.send(value).is_err() {
        debug!("control requester gone before reply");
    }
}
