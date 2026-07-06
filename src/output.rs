//! CLI response formatting — renders daemon responses for the terminal.

use fail2ban_rs::control::Response;

/// Format a remaining-seconds duration as a compact human string.
fn format_relative(remaining_secs: i64) -> String {
    if remaining_secs <= 0 {
        return "expired".to_string();
    }
    let hours = remaining_secs / 3600;
    let mins = (remaining_secs % 3600) / 60;
    match hours {
        0 => format!("{mins}m remaining"),
        _ => format!("{hours}h {mins}m remaining"),
    }
}

/// Print the active bans as an aligned table sorted by soonest expiry.
pub(crate) fn print_bans_table(response: &Response) {
    match response {
        Response::Error { message } => {
            eprintln!("Error: {message}");
            std::process::exit(1);
        }
        Response::Ok { data: None, .. } => {
            println!("No active bans.");
        }
        Response::Ok {
            data: Some(data), ..
        } => {
            let Some(bans) = data.get("bans").and_then(|v| v.as_array()) else {
                println!("No active bans.");
                return;
            };
            if bans.is_empty() {
                println!("No active bans.");
                return;
            }

            let now = chrono::Utc::now().timestamp();

            // Collect and sort by expires_at ascending (soonest first).
            let mut rows: Vec<_> = bans
                .iter()
                .filter_map(|b| {
                    let ip = b.get("ip")?.as_str()?;
                    let jail = b.get("jail")?.as_str()?;
                    let banned_at = b.get("banned_at")?.as_i64()?;
                    let expires_at = b.get("expires_at").and_then(serde_json::Value::as_i64);
                    Some((ip.to_string(), jail.to_string(), banned_at, expires_at))
                })
                .collect();
            rows.sort_by_key(|r| r.3.unwrap_or(i64::MAX));

            // Compute column widths.
            let ip_width = rows.iter().map(|r| r.0.len()).max().unwrap_or(2).max(2);

            println!(
                "{:<6}  {:<ip_w$}  {:<17}  EXPIRES",
                "JAIL",
                "IP",
                "BANNED",
                ip_w = ip_width
            );

            for (ip, jail, banned_at, expires_at) in &rows {
                let banned_dt = chrono::DateTime::from_timestamp(*banned_at, 0).map_or_else(
                    || "-".to_string(),
                    |dt| dt.format("%d %b %H:%M").to_string(),
                );
                let expires = match expires_at {
                    Some(exp) => format_relative(exp - now),
                    None => "permanent".to_string(),
                };
                println!("{jail:<6}  {ip:<ip_width$}  {banned_dt:<17}  {expires}",);
            }
            println!("\nTotal: {} active ban(s)", rows.len());
        }
    }
}

/// Print the active bans as JSONL — one JSON object per line.
pub(crate) fn print_bans_jsonl(response: &Response) {
    match response {
        Response::Error { message } => {
            eprintln!("Error: {message}");
            std::process::exit(1);
        }
        Response::Ok { data: None, .. } => {}
        Response::Ok {
            data: Some(data), ..
        } => {
            if let Some(bans) = data.get("bans").and_then(|v| v.as_array()) {
                for b in bans {
                    let jail = b.get("jail").and_then(|v| v.as_str()).unwrap_or("");
                    let ip = b.get("ip").and_then(|v| v.as_str()).unwrap_or("");
                    let banned_at = b
                        .get("banned_at")
                        .and_then(serde_json::Value::as_i64)
                        .unwrap_or(0);
                    let expires_at = b.get("expires_at").and_then(serde_json::Value::as_i64);
                    match expires_at {
                        Some(exp) => println!(
                            r#"{{"jail":"{jail}","ip":"{ip}","banned_at":{banned_at},"expires_at":{exp}}}"#
                        ),
                        None => println!(
                            r#"{{"jail":"{jail}","ip":"{ip}","banned_at":{banned_at},"expires_at":null}}"#
                        ),
                    }
                }
            }
        }
    }
}

/// Print a generic daemon response — a message and/or pretty-printed data.
pub(crate) fn print_response(response: &Response) {
    match response {
        Response::Ok { message, data } => {
            if let Some(msg) = message {
                println!("{msg}");
            }
            if let Some(data) = data {
                println!("{}", serde_json::to_string_pretty(data).unwrap_or_default());
            }
        }
        Response::Error { message } => {
            eprintln!("Error: {message}");
            std::process::exit(1);
        }
    }
}
