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

/// Run the control socket listener.
pub async fn run(socket_path: &Path, tx: mpsc::Sender<ControlCmd>, cancel: CancellationToken) {
    // Remove stale socket file.
    let _ = std::fs::remove_file(socket_path);

    // Ensure parent directory exists.
    if let Some(parent) = socket_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let listener = match UnixListener::bind(socket_path) {
        Ok(l) => l,
        Err(e) => {
            error!(error = %e, path = %socket_path.display(), "failed to bind control socket");
            return;
        }
    };

    info!(path = %socket_path.display(), "control socket listening");

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("control socket shutting down");
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

async fn handle_connection(
    mut stream: tokio::net::UnixStream,
    tx: mpsc::Sender<ControlCmd>,
) -> Result<()> {
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

    let mut buf = vec![0u8; len as usize];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| Error::protocol(format!("read response: {e}")))?;

    let response: Response = serde_json::from_slice(&buf)
        .map_err(|e| Error::protocol(format!("parse response: {e}")))?;

    Ok(response)
}
