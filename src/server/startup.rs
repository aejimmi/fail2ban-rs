//! Startup and shutdown helpers — legacy-state migration and signal handling.

use std::path::Path;

use etchdb::{Store, WalBackend};
use tracing::warn;

use crate::track::persist::{self, BanState};

/// Move an incompatible legacy `state.bin` file aside so a fresh store opens.
///
/// Older versions persisted a single file; the current store expects a
/// directory. When a regular file is found it is a legacy format that cannot
/// be restored — it is preserved at `<state>.bin.bak` and the operator is
/// warned that previous bans were NOT restored.
pub(super) async fn handle_legacy_state(state_dir: &Path) -> crate::error::Result<()> {
    let is_file = tokio::fs::metadata(state_dir)
        .await
        .map(|m| m.is_file())
        .unwrap_or(false);
    if !is_file {
        return Ok(());
    }
    let backup = state_dir.with_extension("bin.bak");
    warn!(
        phase = "startup",
        old = %state_dir.display(),
        backup = %backup.display(),
        "legacy state format is incompatible; previous bans were NOT restored; \
         original preserved at the backup path"
    );
    tokio::fs::rename(state_dir, &backup).await.map_err(|e| {
        crate::error::Error::io(
            format!("renaming old state file: {}", state_dir.display()),
            e,
        )
    })
}

/// Open the WAL-backed ban store, migrating an incompatible schema aside.
///
/// [`handle_legacy_state`] handles the very old single-*file* format; this
/// handles the current directory WAL whose on-disk *schema* no longer matches
/// this build (e.g. after the `ban_counts` layout change). On
/// [`crate::error::Error::SchemaMismatch`] the store directory is renamed to a
/// unique `.bak-<ts>` sibling and a fresh store is opened — bans are not
/// restored, but the daemon starts cleanly instead of misreading old bytes.
pub(super) async fn open_store_migrating(
    state_dir: &Path,
) -> crate::error::Result<Store<BanState, WalBackend<BanState>>> {
    match persist::open_ban_store(state_dir.to_path_buf()) {
        Ok(store) => Ok(store),
        Err(reason @ crate::error::Error::SchemaMismatch { .. }) => {
            migrate_incompatible_wal(state_dir, &reason).await?;
            persist::open_ban_store(state_dir.to_path_buf())
        }
        Err(e) => Err(e),
    }
}

/// Rename an incompatible WAL directory aside to a unique backup sibling.
async fn migrate_incompatible_wal(
    state_dir: &Path,
    reason: &crate::error::Error,
) -> crate::error::Result<()> {
    let backup = timestamped_backup_path(state_dir);
    warn!(
        phase = "startup",
        old = %state_dir.display(),
        backup = %backup.display(),
        reason = %reason,
        "state schema is incompatible; previous bans were NOT restored; \
         original preserved at the backup path"
    );
    tokio::fs::rename(state_dir, &backup).await.map_err(|e| {
        crate::error::Error::io(
            format!("renaming incompatible state dir: {}", state_dir.display()),
            e,
        )
    })
}

/// Build a unique `<name>.bak-<unix_ts>` sibling path so migrating aside never
/// collides with a backup left by an earlier migration.
fn timestamped_backup_path(state_dir: &Path) -> std::path::PathBuf {
    let ts = chrono::Utc::now().timestamp();
    let mut name = state_dir
        .file_name()
        .map_or_else(|| std::ffi::OsString::from("state"), ToOwned::to_owned);
    name.push(format!(".bak-{ts}"));
    state_dir.with_file_name(name)
}

#[cfg(unix)]
pub(super) async fn signal_sighup() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut stream = match signal(SignalKind::hangup()) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(
                phase = "startup",
                signal = "SIGHUP",
                error = %e,
                "signal handler register failed"
            );
            std::future::pending::<()>().await;
            return;
        }
    };
    stream.recv().await;
}

#[cfg(unix)]
pub(super) async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sigint = match signal(SignalKind::interrupt()) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(
                phase = "startup",
                signal = "SIGINT",
                error = %e,
                "signal handler register failed"
            );
            std::future::pending::<()>().await;
            return;
        }
    };
    let mut sigterm = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(
                phase = "startup",
                signal = "SIGTERM",
                error = %e,
                "signal handler register failed"
            );
            std::future::pending::<()>().await;
            return;
        }
    };

    tokio::select! {
        _ = sigint.recv() => {}
        _ = sigterm.recv() => {}
    }
}

#[cfg(not(unix))]
pub(super) async fn signal_sighup() {
    std::future::pending::<()>().await;
}

#[cfg(not(unix))]
pub(super) async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
