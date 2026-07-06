//! Webhook notification on ban events.
//!
//! Fires a non-blocking HTTP POST via `curl` subprocess. Webhook failures
//! never affect the ban pipeline — errors are logged and discarded.

use std::net::IpAddr;

use tracing::warn;

/// Returns `true` only if `url` uses an `http://` or `https://` scheme.
///
/// This guards against scheme laundering: without it, `curl` would happily
/// accept `file://`, `gopher://`, `dict://`, etc. Validation belongs at the
/// config layer too, but this backend never trusts its caller.
#[must_use]
fn is_http_url(url: &str) -> bool {
    url.starts_with("http://") || url.starts_with("https://")
}

/// Build the `curl` argument vector for a webhook POST.
///
/// The `--` terminator guarantees `url` is always treated as a positional
/// argument, never as an option — so a URL beginning with `-` (e.g.
/// `-o/etc/cron.d/x`) cannot be laundered into a curl flag.
#[must_use]
fn curl_args<'a>(body: &'a str, url: &'a str) -> Vec<&'a str> {
    vec![
        "-s",
        "-X",
        "POST",
        "-H",
        "Content-Type: application/json",
        "--max-time",
        "10",
        "-d",
        body,
        "--",
        url,
    ]
}

/// Fire a webhook notification for a ban event.
///
/// Spawns a `curl` subprocess in the background. Returns immediately.
/// Non-`http(s)` URLs are refused and logged without spawning anything.
pub fn notify_ban(url: &str, ip: IpAddr, jail: &str, ban_time: i64) {
    if !is_http_url(url) {
        warn!(url = %url, "webhook: refusing non-http(s) URL");
        return;
    }

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
            .args(curl_args(&body, &url))
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
///
/// Non-`http(s)` URLs are refused and logged without spawning anything.
pub fn notify_unban(url: &str, ip: IpAddr, jail: &str) {
    if !is_http_url(url) {
        warn!(url = %url, "webhook: refusing non-http(s) URL");
        return;
    }

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
            .args(curl_args(&body, &url))
            .output()
            .await;

        if let Err(e) = result {
            warn!(url = %url, error = %e, "webhook: curl not available");
        }
    });
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
#[path = "webhook_test.rs"]
mod webhook_test;
