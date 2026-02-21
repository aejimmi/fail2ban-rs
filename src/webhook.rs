//! Webhook notification on ban events.
//!
//! Fires a non-blocking HTTP POST via `curl` subprocess. Webhook failures
//! never affect the ban pipeline — errors are logged and discarded.

use std::net::IpAddr;

use tracing::warn;

/// Fire a webhook notification for a ban event.
///
/// Spawns a `curl` subprocess in the background. Returns immediately.
pub fn notify_ban(url: &str, ip: IpAddr, jail: &str, ban_time: i64) {
    let payload = serde_json::json!({
        "event": "ban",
        "ip": ip.to_string(),
        "jail": jail,
        "ban_time": ban_time,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });

    let body = match serde_json::to_string(&payload) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "webhook: failed to serialize payload");
            return;
        }
    };

    let url = url.to_string();
    tokio::spawn(async move {
        let result = tokio::process::Command::new("curl")
            .args([
                "-s",
                "-X",
                "POST",
                "-H",
                "Content-Type: application/json",
                "-m",
                "10",
                "-d",
                &body,
                &url,
            ])
            .output()
            .await;

        match result {
            Ok(output) if !output.status.success() => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                warn!(url = %url, stderr = %stderr, "webhook POST failed");
            }
            Err(e) => {
                warn!(url = %url, error = %e, "webhook: curl not available");
            }
            _ => {}
        }
    });
}

/// Fire a webhook notification for an unban event.
pub fn notify_unban(url: &str, ip: IpAddr, jail: &str) {
    let payload = serde_json::json!({
        "event": "unban",
        "ip": ip.to_string(),
        "jail": jail,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });

    let body = match serde_json::to_string(&payload) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "webhook: failed to serialize payload");
            return;
        }
    };

    let url = url.to_string();
    tokio::spawn(async move {
        let result = tokio::process::Command::new("curl")
            .args([
                "-s",
                "-X",
                "POST",
                "-H",
                "Content-Type: application/json",
                "-m",
                "10",
                "-d",
                &body,
                &url,
            ])
            .output()
            .await;

        if let Err(e) = result {
            warn!(url = %url, error = %e, "webhook: curl not available");
        }
    });
}
