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
use tracing::{debug, error, info, warn};

use crate::error::{Error, Result};

/// Maximum size of a request payload the daemon will read (64 KiB).
/// Requests are tiny commands; anything larger is malformed or hostile.
pub const MAX_REQUEST_BYTES: u32 = 64 * 1024;

/// Maximum size of a response payload (16 MiB).
///
/// Responses can legitimately be large (`list-bans` grows with every active
/// ban, roughly 120 bytes each, so ~130k bans fit). The client refuses any
/// advertised length above this to bound allocation against a malformed or
/// compromised peer, and the daemon refuses to send a response above it,
/// substituting a clear error instead.
pub const MAX_RESPONSE_BYTES: u32 = 16 * 1024 * 1024;

/// Commands from the CLI.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    /// Get overall status.
    Status,
    /// List all active bans.
    ListBans,
    /// Get saved log lines for one active ban.
    BanLogs { ip: IpAddr, jail: String },
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
    if let Err(e) = std::fs::remove_file(socket_path)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        warn!(phase = "startup", error = %e, "stale control socket remove failed");
    }

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
    restrict_socket(socket_path);
    info!(
        phase = "startup",
        path = %socket_path.display(),
        "control socket listening"
    );
    accept_loop(&listener, &tx, &cancel).await;
    info!(phase = "shutdown", "control socket stopping");
    if let Err(e) = std::fs::remove_file(socket_path) {
        debug!(error = %e, "control socket remove failed");
    }
}

/// Restrict the socket to owner+group so no other local user can connect;
/// the parent dir's 0o750 covers the moment between bind and this chmod.
fn restrict_socket(socket_path: &Path) {
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
}

/// Accept connections until cancelled, serving each on its own task.
async fn accept_loop(
    listener: &UnixListener,
    tx: &mpsc::Sender<ControlCmd>,
    cancel: &CancellationToken,
) {
    loop {
        let accept = tokio::select! {
            () = cancel.cancelled() => return,
            accept = listener.accept() => accept,
        };
        match accept {
            Ok((stream, _)) => {
                let tx = tx.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, tx).await {
                        warn!(error = %e, "control connection error");
                    }
                });
            }
            Err(e) => warn!(error = %e, "accept error"),
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

/// Serve one control connection: read a request frame, forward it to the
/// daemon, and write the response frame.
async fn handle_connection(
    mut stream: tokio::net::UnixStream,
    tx: mpsc::Sender<ControlCmd>,
) -> Result<()> {
    #[cfg(target_os = "linux")]
    check_peer_cred(&stream)?;

    let buf = read_frame(&mut stream, MAX_REQUEST_BYTES, "message", "payload").await?;
    let request: Request =
        serde_json::from_slice(&buf).map_err(|e| Error::protocol(format!("parse request: {e}")))?;

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

    let json = encode_response(&response)?;
    write_frame(&mut stream, &json).await
}

/// Read one `[u32 LE length][payload]` frame, rejecting a declared length
/// above `max` before allocating. `what` names the frame in the size error
/// ("{what} too large"); `part` names it in read errors.
async fn read_frame(
    stream: &mut tokio::net::UnixStream,
    max: u32,
    what: &str,
    part: &str,
) -> Result<Vec<u8>> {
    let len = stream
        .read_u32_le()
        .await
        .map_err(|e| Error::protocol(format!("read {part} length: {e}")))?;
    if len > max {
        return Err(Error::protocol(format!("{what} too large: {len}")));
    }
    let mut buf = vec![0u8; len as usize];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| Error::protocol(format!("read {part}: {e}")))?;
    Ok(buf)
}

/// Serialize a response, replacing it with an error response when it would
/// exceed [`MAX_RESPONSE_BYTES`] so the client gets a clear message instead
/// of a frame it must reject.
pub(crate) fn encode_response(response: &Response) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(response)
        .map_err(|e| Error::protocol(format!("serialize response: {e}")))?;
    if json.len() <= MAX_RESPONSE_BYTES as usize {
        return Ok(json);
    }
    warn!(
        size = json.len(),
        limit = MAX_RESPONSE_BYTES,
        "control response exceeds size limit, sending error instead"
    );
    let err = Response::error(format!(
        "response too large: {} bytes exceeds limit of {MAX_RESPONSE_BYTES} bytes",
        json.len()
    ));
    serde_json::to_vec(&err).map_err(|e| Error::protocol(format!("serialize response: {e}")))
}

/// Write one `[u32 LE length][payload]` frame.
async fn write_frame(stream: &mut tokio::net::UnixStream, payload: &[u8]) -> Result<()> {
    let len = u32::try_from(payload.len())
        .map_err(|_| Error::protocol(format!("frame too large: {}", payload.len())))?;
    stream
        .write_u32_le(len)
        .await
        .map_err(|e| Error::protocol(format!("write length: {e}")))?;
    stream
        .write_all(payload)
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
    write_frame(&mut stream, &json).await?;

    // Cap the daemon-supplied length so a compromised or buggy daemon cannot
    // make the client allocate unbounded memory. Responses get a larger bound
    // than requests because list-bans scales with the number of active bans.
    let buf = read_frame(&mut stream, MAX_RESPONSE_BYTES, "response", "response").await?;
    serde_json::from_slice(&buf).map_err(|e| Error::protocol(format!("parse response: {e}")))
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
