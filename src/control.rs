//! Unix socket control listener for CLI commands.
//!
//! Protocol: `[4-byte LE length][JSON payload]`
//! Used by the CLI to query status, ban/unban IPs, and trigger reloads.

use std::net::IpAddr;
use std::path::Path;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::error::{Error, Result};

/// Commands from the CLI.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    /// Get overall status.
    Status,
    /// List all active bans.
    ListBans,
    /// Ban an IP in a specific jail.
    Ban { ip: IpAddr, jail: String },
    /// Unban an IP from a specific jail.
    Unban { ip: IpAddr, jail: String },
    /// Reload configuration.
    Reload,
    /// Get daemon statistics.
    Stats,
}

/// Response from the daemon.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Response {
    Ok {
        #[serde(skip_serializing_if = "Option::is_none")]
        message: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        data: Option<serde_json::Value>,
    },
    Error {
        message: String,
    },
}

impl Response {
    pub fn ok(message: impl Into<String>) -> Self {
        Self::Ok {
            message: Some(message.into()),
            data: None,
        }
    }

    pub fn ok_data(data: serde_json::Value) -> Self {
        Self::Ok {
            message: None,
            data: Some(data),
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self::Error {
            message: message.into(),
        }
    }
}

/// A control command with a response channel.
pub struct ControlCmd {
    pub request: Request,
    pub respond: oneshot::Sender<Response>,
}

/// Remove any stale socket and ensure the parent directory exists with
/// owner-only+group traversal permissions (`0o750`).
fn prepare_socket_path(socket_path: &Path) {
    // Removing a nonexistent stale socket is expected and harmless.
    let _ = std::fs::remove_file(socket_path);

    let Some(parent) = socket_path.parent() else {
        return;
    };
    if let Err(e) = std::fs::create_dir_all(parent) {
        warn!(phase = "startup", error = %e, "control socket parent dir create failed");
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o750)) {
            warn!(phase = "startup", error = %e, "control socket parent dir permissions failed");
        }
    }
}

/// Bind the control socket. The bind→chmod gap is not closed with `umask`
/// because umask is process-global and racing tasks (WAL/state file creation)
/// would inherit it; instead the parent directory's `0o750` mode — applied
/// before bind in `prepare_socket_path` — gates access during the window,
/// and the explicit `set_permissions` below tightens the socket itself.
fn bind_socket(socket_path: &Path) -> std::io::Result<UnixListener> {
    UnixListener::bind(socket_path)
}

/// Run the control socket listener.
pub async fn run(socket_path: &Path, tx: mpsc::Sender<ControlCmd>, cancel: CancellationToken) {
    prepare_socket_path(socket_path);

    let listener = match bind_socket(socket_path) {
        Ok(l) => l,
        Err(e) => {
            error!(
                phase = "startup",
                path = %socket_path.display(),
                error = %e,
                "control socket bind failed"
            );
            return;
        }
    };

    // Restrict the socket to owner+group so no other local user can connect;
    // the parent dir's 0o750 covers the moment between bind and this chmod.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) =
            std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o660))
        {
            warn!(
                phase = "startup",
                error = %e,
                "control socket permissions failed"
            );
        }
    }

    info!(
        phase = "startup",
        path = %socket_path.display(),
        "control socket listening"
    );

    loop {
        tokio::select! {
            () = cancel.cancelled() => {
                info!(phase = "shutdown", "control socket stopping");
                let _ = std::fs::remove_file(socket_path);
                break;
            }
            accept = listener.accept() => {
                match accept {
                    Ok((stream, _)) => {
                        let tx = tx.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(stream, tx).await {
                                warn!(error = %e, "control connection error");
                            }
                        });
                    }
                    Err(e) => {
                        warn!(error = %e, "accept error");
                    }
                }
            }
        }
    }
}

/// Reject connections from peers that are neither `root` nor the daemon's own
/// effective UID. Prevents an unprivileged local user with directory access
/// from driving the control socket. Linux-only (uses `SO_PEERCRED`); a no-op on
/// other platforms, where the daemon is not run in production.
#[cfg(target_os = "linux")]
fn check_peer_cred(stream: &tokio::net::UnixStream) -> Result<()> {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};

    let cred = getsockopt(stream, PeerCredentials)
        .map_err(|e| Error::protocol(format!("peer credential lookup failed: {e}")))?;
    let peer_uid = cred.uid();
    let my_uid = nix::unistd::geteuid().as_raw();
    if peer_uid != 0 && peer_uid != my_uid {
        warn!(
            peer_uid,
            daemon_uid = my_uid,
            "control socket: rejecting unauthorized peer"
        );
        return Err(Error::protocol(format!(
            "unauthorized control peer uid {peer_uid}"
        )));
    }
    Ok(())
}

async fn handle_connection(
    mut stream: tokio::net::UnixStream,
    tx: mpsc::Sender<ControlCmd>,
) -> Result<()> {
    #[cfg(target_os = "linux")]
    check_peer_cred(&stream)?;

    // Read length prefix.
    let len = stream
        .read_u32_le()
        .await
        .map_err(|e| Error::protocol(format!("read length: {e}")))?;

    if len > 1024 * 64 {
        return Err(Error::protocol(format!("message too large: {len}")));
    }

    // Read JSON payload.
    let mut buf = vec![0u8; len as usize];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| Error::protocol(format!("read payload: {e}")))?;

    let request: Request =
        serde_json::from_slice(&buf).map_err(|e| Error::protocol(format!("parse request: {e}")))?;

    // Send to handler and wait for response.
    let (resp_tx, resp_rx) = oneshot::channel();
    let cmd = ControlCmd {
        request,
        respond: resp_tx,
    };

    tx.send(cmd)
        .await
        .map_err(|_| Error::protocol("handler channel closed"))?;

    let response = resp_rx
        .await
        .map_err(|_| Error::protocol("response channel dropped"))?;

    // Write response.
    let json = serde_json::to_vec(&response)
        .map_err(|e| Error::protocol(format!("serialize response: {e}")))?;
    stream
        .write_u32_le(json.len() as u32)
        .await
        .map_err(|e| Error::protocol(format!("write length: {e}")))?;
    stream
        .write_all(&json)
        .await
        .map_err(|e| Error::protocol(format!("write payload: {e}")))?;

    Ok(())
}

/// Send a request to the daemon control socket and return the response.
pub async fn send_request(socket_path: &Path, request: &Request) -> Result<Response> {
    let mut stream = tokio::net::UnixStream::connect(socket_path)
        .await
        .map_err(|e| Error::protocol(format!("connect to {}: {e}", socket_path.display())))?;

    let json = serde_json::to_vec(request)
        .map_err(|e| Error::protocol(format!("serialize request: {e}")))?;

    stream
        .write_u32_le(json.len() as u32)
        .await
        .map_err(|e| Error::protocol(format!("write length: {e}")))?;
    stream
        .write_all(&json)
        .await
        .map_err(|e| Error::protocol(format!("write payload: {e}")))?;

    let len = stream
        .read_u32_le()
        .await
        .map_err(|e| Error::protocol(format!("read response length: {e}")))?;

    // Cap the daemon-supplied length so a compromised or buggy daemon cannot
    // make the client allocate unbounded memory. Same 64 KiB limit the server
    // enforces on inbound requests.
    if len > 1024 * 64 {
        return Err(Error::protocol(format!("response too large: {len}")));
    }

    let mut buf = vec![0u8; len as usize];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| Error::protocol(format!("read response: {e}")))?;

    let response: Response = serde_json::from_slice(&buf)
        .map_err(|e| Error::protocol(format!("parse response: {e}")))?;

    Ok(response)
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::needless_pass_by_value
)]
#[path = "control_test.rs"]
mod control_test;
