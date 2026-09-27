//! Log watcher lifecycle — plan compilation, spawning, and gap-free stop.
//!
//! Every spawned watcher's [`JoinHandle`] is kept alongside the shared
//! cancellation token. Stopping cancels the token and awaits each handle
//! (bounded by [`STOP_TIMEOUT`]) to collect the [`ResumePoint`] it reached,
//! so a replacement watcher continues exactly where the old one stopped and
//! no log line is skipped or read twice across a reload.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::{JoinError, JoinHandle};
use tokio::time::error::Elapsed;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::config::{Config, JailConfig, LogBackend};
use crate::detect::ResumePoint;
use crate::detect::date::DateParser;
use crate::detect::ignore::IgnoreList;
use crate::detect::matcher::JailMatcher;
use crate::detect::watcher::Failure;

/// Upper bound on waiting for all old watchers to report their position.
const STOP_TIMEOUT: Duration = Duration::from_secs(5);

/// Handle to one running watcher task, keyed by jail name.
pub(super) type WatcherHandle = (String, JoinHandle<Option<ResumePoint>>);

/// Pre-compiled watcher plan for a single jail.
pub(super) struct WatcherPlan {
    pub(super) name: String,
    pub(super) jail: JailConfig,
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

/// Spawn one watcher task per plan under child tokens of `cancel`.
///
/// Each jail found in `resume` starts from its recorded position; the rest
/// start from their default (end of file / journal tail).
pub(super) fn spawn_watchers(
    watcher_plan: Vec<WatcherPlan>,
    failure_tx: &mpsc::Sender<Failure>,
    cancel: &CancellationToken,
    phase: &'static str,
    mut resume: HashMap<String, ResumePoint>,
    handoff: &Arc<AtomicBool>,
) -> Vec<WatcherHandle> {
    watcher_plan
        .into_iter()
        .map(|plan| {
            let start = resume.remove(&plan.name);
            let name = plan.name.clone();
            let handle = spawn_one(
                plan,
                failure_tx.clone(),
                cancel.child_token(),
                phase,
                start,
                handoff.clone(),
            );
            (name, handle)
        })
        .collect()
}

/// Spawn the file or journal watcher for a single plan.
fn spawn_one(
    plan: WatcherPlan,
    tx: mpsc::Sender<Failure>,
    cancel: CancellationToken,
    phase: &'static str,
    start: Option<ResumePoint>,
    handoff: Arc<AtomicBool>,
) -> JoinHandle<Option<ResumePoint>> {
    if plan.jail.log_backend == LogBackend::Systemd {
        return spawn_journal(plan, tx, cancel, phase, start, handoff);
    }
    tokio::spawn(crate::detect::watcher::run_supervised_from(
        plan.name,
        plan.jail.log_path,
        plan.matcher,
        plan.date_parser,
        plan.ignore_list,
        tx,
        cancel,
        phase,
        start,
        handoff,
    ))
}

/// Spawn a journald watcher for a systemd-backed plan.
fn spawn_journal(
    plan: WatcherPlan,
    tx: mpsc::Sender<Failure>,
    cancel: CancellationToken,
    phase: &'static str,
    start: Option<ResumePoint>,
    handoff: Arc<AtomicBool>,
) -> JoinHandle<Option<ResumePoint>> {
    tokio::spawn(crate::detect::journal::run_supervised_from(
        plan.name,
        plan.jail.journalmatch,
        plan.matcher,
        plan.date_parser,
        plan.ignore_list,
        tx,
        cancel,
        phase,
        start,
        handoff,
    ))
}

/// The running watcher set: a shared cancellation token plus every task's
/// join handle.
#[derive(Default)]
pub(super) struct Watchers {
    cancel: CancellationToken,
    handles: Vec<WatcherHandle>,
    handoff: Arc<AtomicBool>,
}

impl Watchers {
    /// Spawn watchers for `plan` under a fresh token.
    pub(super) fn spawn(
        plan: Vec<WatcherPlan>,
        failure_tx: &mpsc::Sender<Failure>,
        phase: &'static str,
        resume: HashMap<String, ResumePoint>,
    ) -> Self {
        let cancel = CancellationToken::new();
        let handoff = Arc::new(AtomicBool::new(false));
        let handles = spawn_watchers(plan, failure_tx, &cancel, phase, resume, &handoff);
        Self {
            cancel,
            handles,
            handoff,
        }
    }

    /// Reload must wait for every watcher to deliver queued failures and
    /// report its position; timing out would restart it at EOF.
    pub(super) async fn stop_for_reload(&mut self) -> HashMap<String, ResumePoint> {
        self.handoff.store(true, Ordering::Release);
        self.cancel.cancel();
        let mut points = HashMap::new();
        for (name, handle) in self.handles.drain(..) {
            if let Some(point) = resume_point(&name, Ok(handle.await)) {
                points.insert(name, point);
            }
        }
        points
    }

    /// Cancel every watcher and collect the positions they stopped at.
    ///
    /// All handles share one [`STOP_TIMEOUT`] deadline. A watcher that times
    /// out, panics, or reports no position is logged and omitted, so its
    /// jail's replacement starts from the default position.
    pub(super) async fn stop(&mut self) -> HashMap<String, ResumePoint> {
        self.cancel.cancel();
        let deadline = tokio::time::Instant::now() + STOP_TIMEOUT;
        let mut points = HashMap::new();
        for (name, handle) in self.handles.drain(..) {
            let outcome = tokio::time::timeout_at(deadline, handle).await;
            if let Some(point) = resume_point(&name, outcome) {
                points.insert(name, point);
            }
        }
        points
    }
}

/// Unpack a watcher's stop outcome, logging why no position is available.
fn resume_point(
    name: &str,
    outcome: Result<Result<Option<ResumePoint>, JoinError>, Elapsed>,
) -> Option<ResumePoint> {
    match outcome {
        Ok(Ok(Some(point))) => Some(point),
        Ok(Ok(None)) => {
            debug!(jail = %name, "watcher stopped without a resume point");
            None
        }
        Ok(Err(e)) => {
            warn!(jail = %name, error = %e, "watcher task failed; jail restarts from default position");
            None
        }
        Err(_) => {
            warn!(jail = %name, "watcher stop timed out; jail restarts from default position");
            None
        }
    }
}

impl Drop for Watchers {
    /// Never leak running watchers: dropping the set cancels them (a no-op
    /// if [`Watchers::stop`] already ran).
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::needless_pass_by_value
)]
#[path = "watchers_test.rs"]
mod watchers_test;
