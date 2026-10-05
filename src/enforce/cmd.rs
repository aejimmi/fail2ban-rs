//! Shared subprocess runner for firewall backends.
//!
//! Every backend shells out (`nft`, `iptables`, `ipset`, `sh -c`). A hung
//! child — e.g. `iptables` blocked on the xtables lock, or a user script that
//! never exits — must not freeze the single executor task, so every command
//! runs under [`COMMAND_TIMEOUT`](crate::enforce::cmd::COMMAND_TIMEOUT). Each child leads its own process group, and
//! when the timeout fires the whole group is `SIGKILL`ed: killing only the
//! direct child (e.g. `sh`) would leave background grandchildren alive, still
//! holding the stdout pipe.

use std::ffi::OsStr;
use std::process::{Output, Stdio};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt};

use nix::errno::Errno;
use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use tracing::{debug, warn};

use crate::error::{Error, Result};

/// Upper bound on duplicate copies of one rule removed per teardown.
///
/// Older releases could stack duplicate rules across re-inits; a teardown
/// removes every copy, bounded so a `-D` that "succeeds" without removing
/// anything can never loop forever.
pub(crate) const MAX_RULE_DELETES: usize = 16;

/// Upper bound on how long any single firewall command may run.
///
/// Firewall commands normally finish in milliseconds; 30s leaves ample room
/// for a contended xtables lock or a slow user script while still bounding
/// how long one stuck command can stall ban enforcement.
pub(crate) const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

/// Complete native firewall listings must fit this bound. Oversized listings
/// fail explicitly rather than presenting truncated state to reconciliation.
const MAX_STDOUT_BYTES: usize = 16 * 1024 * 1024;
/// Retain a bounded diagnostic prefix while draining the rest of stderr.
const MAX_STDERR_BYTES: usize = 64 * 1024;
const TRUNCATED: &[u8] = b"\n[stderr truncated]\n";

/// Run `program args...` under [`COMMAND_TIMEOUT`] and capture its output.
///
/// A spawn failure or timeout is an error; a nonzero exit is *not* — callers
/// that need to interpret the exit status (e.g. `ipset test`) inspect it.
pub(crate) async fn output<P, S>(program: P, label: &str, args: &[S]) -> Result<Output>
where
    P: AsRef<OsStr>,
    S: AsRef<OsStr>,
{
    output_with_timeout(program, label, args, COMMAND_TIMEOUT).await
}

/// Like [`output`], with an explicit timeout.
pub(crate) async fn output_with_timeout<P, S>(
    program: P,
    label: &str,
    args: &[S],
    limit: Duration,
) -> Result<Output>
where
    P: AsRef<OsStr>,
    S: AsRef<OsStr>,
{
    execute(program, label, args, limit, true).await
}

/// Drain both pipes concurrently before reaping the leader. Keeping the leader
/// unreaped preserves its process-group identity if a background child keeps a
/// pipe open until the timeout or the output limit fires.
async fn execute<P, S>(
    program: P,
    label: &str,
    args: &[S],
    limit: Duration,
    capture_stdout: bool,
) -> Result<Output>
where
    P: AsRef<OsStr>,
    S: AsRef<OsStr>,
{
    let mut child = spawn_in_group(program, label, args)?;
    let pgid = child.id();
    let result = tokio::time::timeout(limit, collect(&mut child, label, capture_stdout)).await;
    let error = match result {
        Ok(Ok(out)) => return Ok(out),
        Ok(Err(error)) => error,
        Err(_) => Error::firewall(format!(
            "{label} command timed out after {}s and was killed",
            limit.as_secs_f64()
        )),
    };
    abort_and_reap(&mut child, pgid, label).await;
    Err(error)
}

/// Drain stdout and stderr concurrently, then reap the leader. The leader is
/// only waited on once both pipes hit EOF, so it stays unreaped (and its
/// process group addressable) for as long as any pipe is still open.
async fn collect(
    child: &mut tokio::process::Child,
    label: &str,
    capture_stdout: bool,
) -> Result<Output> {
    let stdout_max = if capture_stdout { MAX_STDOUT_BYTES } else { 0 };
    let (stdout, stderr) = tokio::try_join!(
        read_bounded(
            child.stdout.take(),
            stdout_max,
            !capture_stdout,
            label,
            "stdout"
        ),
        read_bounded(child.stderr.take(), MAX_STDERR_BYTES, true, label, "stderr"),
    )?;
    let status = child
        .wait()
        .await
        .map_err(|e| Error::firewall(format!("{label} command failed: {e}")))?;
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

/// Kill a timed-out or over-limit command's process group while the leader is
/// still unreaped, then reap the leader so it never lingers as a zombie.
async fn abort_and_reap(child: &mut tokio::process::Child, pgid: Option<u32>, label: &str) {
    kill_group(pgid, label);
    // Also request a direct kill in case signalling the group failed.
    if let Err(e) = child.start_kill() {
        debug!(%label, error = %e, "direct kill of aborted command failed");
    }
    if let Err(e) = child.wait().await {
        warn!(%label, error = %e, "failed to reap aborted command");
    }
}

/// Read `pipe` to EOF, keeping at most `max_bytes`. Past the bound, either
/// keep a truncated prefix ending in a marker (`truncate`) or fail with
/// [`Error::FirewallOutputLimit`].
async fn read_bounded<R: AsyncRead + Unpin>(
    pipe: Option<R>,
    max_bytes: usize,
    truncate: bool,
    label: &str,
    stream: &'static str,
) -> Result<Vec<u8>> {
    let Some(mut pipe) = pipe else {
        return Ok(Vec::new());
    };
    let mut bytes = Vec::new();
    let mut chunk = Box::new([0u8; 8192]);
    let mut truncated = false;
    loop {
        let n = pipe
            .read(&mut *chunk)
            .await
            .map_err(|e| Error::firewall(format!("{label} {stream} read failed: {e}")))?;
        let Some(data) = chunk.get(..n).filter(|d| !d.is_empty()) else {
            break;
        };
        if !append_bounded(&mut bytes, data, max_bytes) {
            if !truncate {
                return Err(output_limit(label, stream, max_bytes));
            }
            truncated = true;
        }
    }
    if truncated {
        mark_truncated(&mut bytes, max_bytes);
    }
    Ok(bytes)
}

/// Append as much of `data` as fits under `max_bytes`. Returns `false` when
/// some of `data` did not fit.
fn append_bounded(bytes: &mut Vec<u8>, data: &[u8], max_bytes: usize) -> bool {
    let remaining = max_bytes.saturating_sub(bytes.len());
    bytes.extend_from_slice(data.get(..data.len().min(remaining)).unwrap_or_default());
    data.len() <= remaining
}

/// Replace the tail of an overflowed buffer with the truncation marker,
/// keeping the result within `max_bytes`.
fn mark_truncated(bytes: &mut Vec<u8>, max_bytes: usize) {
    bytes.truncate(max_bytes.saturating_sub(TRUNCATED.len()));
    bytes.extend_from_slice(TRUNCATED.get(..max_bytes).unwrap_or(TRUNCATED));
}

/// Error for a stream that exceeded its non-truncating output bound.
fn output_limit(label: &str, stream: &'static str, max_bytes: usize) -> Error {
    Error::FirewallOutputLimit {
        label: label.to_string(),
        stream,
        max_bytes,
    }
}

/// Spawn `program args...` as the leader of a new process group, with
/// stdout/stderr captured and stdin closed.
fn spawn_in_group<P, S>(program: P, label: &str, args: &[S]) -> Result<tokio::process::Child>
where
    P: AsRef<OsStr>,
    S: AsRef<OsStr>,
{
    tokio::process::Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .process_group(0)
        .spawn()
        .map_err(|e| Error::firewall(format!("{label} command failed: {e}")))
}

/// `SIGKILL` every process in a timed-out command's process group.
fn kill_group(pgid: Option<u32>, label: &str) {
    let Some(raw) = pgid.and_then(|p| i32::try_from(p).ok()) else {
        debug!(%label, "timed-out command already reaped; no group to kill");
        return;
    };
    match killpg(Pid::from_raw(raw), Signal::SIGKILL) {
        Ok(()) | Err(Errno::ESRCH) => {}
        Err(e) => warn!(%label, pgid = raw, error = %e, "failed to kill timed-out command group"),
    }
}

/// Map a nonzero exit status to an error carrying the trimmed stderr.
pub(crate) fn check_status(label: &str, output: &Output) -> Result<()> {
    if output.status.success() {
        return Ok(());
    }
    Err(status_error(label, output))
}

/// Build the error for a failed exit status, carrying the trimmed stderr.
fn status_error(label: &str, output: &Output) -> Error {
    let stderr = String::from_utf8_lossy(&output.stderr);
    Error::firewall(format!("{label} exit {}: {}", output.status, stderr.trim()))
}

/// Run a command under [`COMMAND_TIMEOUT`], treating a nonzero exit as an error.
pub(crate) async fn run<P, S>(program: P, label: &str, args: &[S]) -> Result<()>
where
    P: AsRef<OsStr>,
    S: AsRef<OsStr>,
{
    let out = execute(program, label, args, COMMAND_TIMEOUT, false).await?;
    check_status(label, &out)
}

/// Flag making `iptables`/`ip6tables` wait for the xtables lock instead of
/// failing immediately (exit 4) when another process holds it. The wait is
/// still bounded by [`COMMAND_TIMEOUT`].
pub(crate) const XTABLES_WAIT: &str = "-w";

/// Exit status `iptables -C` returns when the probed rule does not exist.
pub(crate) const RULE_ABSENT_EXIT: i32 = 1;

/// Prefix an `iptables`/`ip6tables` argv with [`XTABLES_WAIT`].
fn xtables_args<S: AsRef<OsStr>>(args: &[S]) -> Vec<&OsStr> {
    std::iter::once(OsStr::new(XTABLES_WAIT))
        .chain(args.iter().map(AsRef::as_ref))
        .collect()
}

/// [`run`] an `iptables`/`ip6tables` command, waiting for the xtables lock.
pub(crate) async fn xtables_run<P, S>(program: P, label: &str, args: &[S]) -> Result<()>
where
    P: AsRef<OsStr>,
    S: AsRef<OsStr>,
{
    run(program, label, &xtables_args(args)).await
}

/// [`output`] of an `iptables`/`ip6tables` command, waiting for the xtables lock.
pub(crate) async fn xtables_output<P, S>(program: P, label: &str, args: &[S]) -> Result<Output>
where
    P: AsRef<OsStr>,
    S: AsRef<OsStr>,
{
    output(program, label, &xtables_args(args)).await
}

/// Probe whether a rule exists with an iptables `-C` argv.
///
/// Exit 0 means present and [`RULE_ABSENT_EXIT`] means absent; any other
/// outcome (xtables lock contention, bad arguments, a killed child) is an
/// error, never mistaken for "absent".
pub(crate) async fn rule_present<P, S>(program: P, label: &str, check: &[S]) -> Result<bool>
where
    P: AsRef<OsStr>,
    S: AsRef<OsStr>,
{
    let out = xtables_output(program, label, check).await?;
    match out.status.code() {
        Some(0) => Ok(true),
        Some(RULE_ABSENT_EXIT) => Ok(false),
        _ => Err(status_error(label, &out)),
    }
}

/// Run `add` unless the `check` probe (an iptables `-C`) already matches, so
/// re-initialization never stacks duplicate rules. A probe that fails for any
/// reason other than "rule absent" is returned as an error.
pub(crate) async fn ensure_rule<P, S>(program: P, label: &str, check: &[S], add: &[S]) -> Result<()>
where
    P: AsRef<OsStr>,
    S: AsRef<OsStr>,
{
    if rule_present(&program, label, check).await? {
        return Ok(());
    }
    xtables_run(&program, label, add).await
}

/// Delete every copy of a rule: run `delete` while the `check` probe (an
/// iptables `-C`) still matches, at most [`MAX_RULE_DELETES`] times.
///
/// Returns how many copies were deleted. A failing `delete` while the rule
/// still matches, or a probe that fails for any reason other than "rule
/// absent" (e.g. xtables lock contention), is returned as an error rather
/// than treated as success.
pub(crate) async fn delete_all_rules<P, S>(
    program: P,
    label: &str,
    check: &[S],
    delete: &[S],
) -> Result<usize>
where
    P: AsRef<OsStr>,
    S: AsRef<OsStr>,
{
    let mut deleted = 0;
    while deleted < MAX_RULE_DELETES && rule_present(&program, label, check).await? {
        xtables_run(&program, label, delete).await?;
        deleted += 1;
    }
    Ok(deleted)
}

#[cfg(test)]
#[path = "cmd_test.rs"]
mod cmd_test;
