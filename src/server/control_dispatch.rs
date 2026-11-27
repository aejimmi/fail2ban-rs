//! Control-socket request dispatch.
//!
//! Requests that only need the tracker (list/ban/unban/stats) are answered on
//! a spawned task so the daemon's main select loop never blocks on a tracker
//! or firewall response — a slow manual ban cannot delay SIGTERM/SIGHUP
//! handling. `Reload` mutates the daemon's config and watchers, so it runs
//! inline.

use std::net::IpAddr;

use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info};

use crate::config::Config;
use crate::control::{ControlCmd, Request, Response};
use crate::track::TrackerCmd;

use super::reload::{ReloadContext, reload_config};

/// A control request answered purely by the tracker.
pub(super) enum TrackerRequest {
    /// List active bans.
    ListBans,
    /// Show saved log lines for a single ban.
    BanLogs { ip: IpAddr, jail: String },
    /// Manually ban `ip` in `jail` for `ban_time` seconds.
    Ban {
        ip: IpAddr,
        jail: String,
        ban_time: i64,
    },
    /// Manually unban `ip` from `jail`.
    Unban { ip: IpAddr, jail: String },
    /// Runtime statistics.
    Stats,
}

/// How a control request is to be served.
pub(super) enum Dispatch {
    /// Already answered (status, or a request rejected up front).
    Immediate(Response),
    /// A config reload, which needs mutable daemon state.
    Reload,
    /// Forward to the tracker.
    Tracker(TrackerRequest),
}

/// Classify a request, resolving anything that needs the daemon config (the
/// manual ban time) so the tracker leg can run without borrowing it.
pub(super) fn classify_request(request: Request, config: &Config) -> Dispatch {
    match request {
        Request::Status => Dispatch::Immediate(Response::ok("fail2ban-rs is running")),
        Request::ListBans => Dispatch::Tracker(TrackerRequest::ListBans),
        Request::BanLogs { ip, jail } => Dispatch::Tracker(TrackerRequest::BanLogs { ip, jail }),
        Request::Ban { ip, jail } => match resolve_ban_time(config, &jail) {
            Ok(ban_time) => Dispatch::Tracker(TrackerRequest::Ban { ip, jail, ban_time }),
            Err(msg) => Dispatch::Immediate(Response::error(msg)),
        },
        Request::Unban { ip, jail } => Dispatch::Tracker(TrackerRequest::Unban { ip, jail }),
        Request::Reload => Dispatch::Reload,
        Request::Stats => Dispatch::Tracker(TrackerRequest::Stats),
    }
}

/// Serve one control command from the main loop without blocking it on the
/// tracker: tracker requests are answered on a spawned task.
pub(super) async fn dispatch_control(
    ctrl: ControlCmd,
    tracker_cmd_tx: &mpsc::Sender<TrackerCmd>,
    ctx: &mut ReloadContext<'_>,
) {
    match classify_request(ctrl.request, ctx.config) {
        Dispatch::Immediate(response) => send_response(ctrl.respond, response),
        Dispatch::Reload => {
            let response = handle_reload_request(tracker_cmd_tx, ctx).await;
            send_response(ctrl.respond, response);
        }
        Dispatch::Tracker(req) => {
            let tx = tracker_cmd_tx.clone();
            tokio::spawn(async move {
                send_response(ctrl.respond, forward_to_tracker(req, &tx).await);
            });
        }
    }
}

/// Serve a control request to completion (awaiting any tracker response).
///
/// Test seam: exercises the same classify/forward path as [`dispatch_control`]
/// but returns the response directly instead of spawning.
#[cfg(test)]
pub(super) async fn handle_control_request(
    request: Request,
    tracker_cmd_tx: &mpsc::Sender<TrackerCmd>,
    ctx: &mut ReloadContext<'_>,
) -> Response {
    match classify_request(request, ctx.config) {
        Dispatch::Immediate(response) => response,
        Dispatch::Reload => handle_reload_request(tracker_cmd_tx, ctx).await,
        Dispatch::Tracker(req) => forward_to_tracker(req, tracker_cmd_tx).await,
    }
}

/// Reply to the control client; a disconnected client is not an error.
fn send_response(respond: oneshot::Sender<Response>, response: Response) {
    if respond.send(response).is_err() {
        debug!("control client disconnected before response");
    }
}

/// Send a tracker command built around a fresh reply channel and await it.
async fn ask_tracker<T>(
    tracker_cmd_tx: &mpsc::Sender<TrackerCmd>,
    build: impl FnOnce(oneshot::Sender<T>) -> TrackerCmd,
) -> Result<T, Response> {
    let (tx, rx) = oneshot::channel();
    if tracker_cmd_tx.send(build(tx)).await.is_err() {
        return Err(Response::error("tracker unavailable"));
    }
    rx.await
        .map_err(|_| Response::error("tracker did not respond"))
}

/// Forward a tracker request and translate the reply into a [`Response`].
pub(super) async fn forward_to_tracker(
    req: TrackerRequest,
    tracker_cmd_tx: &mpsc::Sender<TrackerCmd>,
) -> Response {
    let result = match req {
        TrackerRequest::ListBans => list_bans(tracker_cmd_tx).await,
        TrackerRequest::BanLogs { ip, jail } => ban_logs(tracker_cmd_tx, ip, jail).await,
        TrackerRequest::Ban { ip, jail, ban_time } => {
            manual_ban(tracker_cmd_tx, ip, jail, ban_time).await
        }
        TrackerRequest::Unban { ip, jail } => manual_unban(tracker_cmd_tx, ip, jail).await,
        TrackerRequest::Stats => stats(tracker_cmd_tx).await,
    };
    result.unwrap_or_else(|response| response)
}

/// Ask the tracker for a manual ban; it answers only once the firewall has
/// applied (or failed/timed out applying) the ban.
async fn manual_ban(
    tracker_cmd_tx: &mpsc::Sender<TrackerCmd>,
    ip: IpAddr,
    jail: String,
    ban_time: i64,
) -> Result<Response, Response> {
    let ok_message = format!("banned {ip} in {jail}");
    let result = ask_tracker(tracker_cmd_tx, |respond| TrackerCmd::ManualBan {
        ip,
        jail_id: jail,
        ban_time,
        respond,
    })
    .await?;
    Ok(mutation_response(result, ok_message))
}

async fn manual_unban(
    tracker_cmd_tx: &mpsc::Sender<TrackerCmd>,
    ip: IpAddr,
    jail: String,
) -> Result<Response, Response> {
    let ok_message = format!("unbanned {ip} from {jail}");
    let result = ask_tracker(tracker_cmd_tx, |respond| TrackerCmd::ManualUnban {
        ip,
        jail_id: jail,
        respond,
    })
    .await?;
    Ok(mutation_response(result, ok_message))
}

/// Map a ban/unban result to an ok-with-message or error response.
fn mutation_response(result: crate::error::Result<()>, ok_message: String) -> Response {
    match result {
        Ok(()) => Response::ok(ok_message),
        Err(e) => Response::error(e.to_string()),
    }
}

async fn list_bans(tracker_cmd_tx: &mpsc::Sender<TrackerCmd>) -> Result<Response, Response> {
    let bans = ask_tracker(tracker_cmd_tx, |respond| TrackerCmd::QueryBans { respond }).await?;
    let data: Vec<serde_json::Value> = bans
        .iter()
        .map(|b| {
            serde_json::json!({
                "ip": b.ip.to_string(),
                "jail": b.jail_id,
                "banned_at": b.banned_at,
                "expires_at": b.expires_at,
            })
        })
        .collect();
    Ok(Response::ok_data(serde_json::json!({ "bans": data })))
}

async fn ban_logs(
    tracker_cmd_tx: &mpsc::Sender<TrackerCmd>,
    ip: IpAddr,
    jail: String,
) -> Result<Response, Response> {
    let lines = ask_tracker(tracker_cmd_tx, |respond| TrackerCmd::QueryBanLogs {
        ip,
        jail_id: jail.clone(),
        respond,
    })
    .await?;
    Ok(match lines {
        Some(lines) => Response::ok_data(serde_json::json!({ "lines": lines })),
        None => Response::error(crate::error::Error::NotBanned { ip, jail }.to_string()),
    })
}

async fn stats(tracker_cmd_tx: &mpsc::Sender<TrackerCmd>) -> Result<Response, Response> {
    let stats = ask_tracker(tracker_cmd_tx, |respond| TrackerCmd::GetStats { respond }).await?;
    Ok(match serde_json::to_value(&stats) {
        Ok(v) => Response::ok_data(v),
        Err(e) => Response::error(format!("serialize stats: {e}")),
    })
}

/// Run a config reload requested over the control socket.
async fn handle_reload_request(
    tracker_cmd_tx: &mpsc::Sender<TrackerCmd>,
    ctx: &mut ReloadContext<'_>,
) -> Response {
    info!(
        phase = "reload",
        trigger = "control_socket",
        "config reload starting"
    );
    let result = reload_config(
        ctx.config_path,
        ctx.executor_tx,
        tracker_cmd_tx,
        ctx.config,
        ctx.watchers,
        ctx.failure_tx,
        ctx.logger,
    )
    .await;
    match result {
        Ok(()) => {
            info!(phase = "reload", "config reload complete");
            Response::ok("config reloaded")
        }
        Err(e) => {
            error!(phase = "reload", error = %e, "config reload failed");
            Response::error(format!("reload failed: {e}"))
        }
    }
}

/// Resolve the configured ban time (seconds) for a manual ban on `jail`.
///
/// Returns an error message string when the jail is unknown or disabled, so
/// the caller can reject the request instead of applying a bogus default.
pub(super) fn resolve_ban_time(config: &Config, jail: &str) -> std::result::Result<i64, String> {
    match config.jail.get(jail) {
        Some(cfg) if cfg.enabled => Ok(cfg.ban_time),
        Some(_) => Err(format!("jail '{jail}' is not enabled")),
        None => Err(format!("unknown jail '{jail}'")),
    }
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::needless_pass_by_value
)]
#[path = "control_dispatch_test.rs"]
mod control_dispatch_test;
