//! Startup restore of persisted bans against freshly-initialized backends.

use std::collections::HashMap;

use tracing::{info, warn};

use crate::config::JailConfig;
use crate::error::Result;
use crate::track::state::BanRecord;

use super::FirewallBackend;

/// Initialize firewall rules (chains/sets) for every enabled jail backend.
///
/// This must run before any ban is applied — restored bans target sets and
/// chains that only exist once `init` has run. Aborts on the first failure.
pub async fn init_backends<S: ::std::hash::BuildHasher, S2: ::std::hash::BuildHasher>(
    backends: &HashMap<String, Box<dyn FirewallBackend>, S>,
    jail_configs: &HashMap<String, JailConfig, S2>,
) -> Result<()> {
    for (name, cfg) in jail_configs {
        if !cfg.enabled {
            continue;
        }
        let Some(backend) = backends.get(name) else {
            continue;
        };
        backend.init(name, &cfg.port, &cfg.protocol).await?;
        info!(phase = "startup", jail = %name, "firewall initialized");
    }
    Ok(())
}

/// Initialize firewall backends, then restore saved bans against them.
///
/// Guarantees init happens before any ban is applied so restored bans land in
/// sets/chains that already exist (fixes bans being dropped after a clean
/// restart). Returns the bans that were successfully restored.
pub async fn init_and_restore<S: ::std::hash::BuildHasher, S2: ::std::hash::BuildHasher>(
    bans: &[BanRecord],
    backends: &HashMap<String, Box<dyn FirewallBackend>, S>,
    now: i64,
    jail_configs: &HashMap<String, JailConfig, S2>,
) -> Result<Vec<BanRecord>> {
    init_backends(backends, jail_configs).await?;
    Ok(restore_bans(bans, backends, now, jail_configs).await)
}

/// Restore previously saved bans by re-issuing ban commands.
///
/// Jails with `reban_on_restart = false` are skipped — their firewall state
/// persists independently (e.g. ipset).
pub async fn restore_bans<S: ::std::hash::BuildHasher, S2: ::std::hash::BuildHasher>(
    bans: &[BanRecord],
    backends: &HashMap<String, Box<dyn FirewallBackend>, S>,
    now: i64,
    jail_configs: &HashMap<String, JailConfig, S2>,
) -> Vec<BanRecord> {
    let mut restored = Vec::new();
    for ban in bans {
        // Skip jails that opted out of restore.
        if jail_configs
            .get(&ban.jail_id)
            .is_some_and(|j| !j.reban_on_restart)
        {
            continue;
        }
        // Skip expired bans.
        if let Some(expires) = ban.expires_at
            && expires <= now
        {
            continue;
        }
        let Some(backend) = backends.get(&ban.jail_id) else {
            warn!(
                ip = %ban.ip,
                jail = %ban.jail_id,
                reason = "no_backend",
                "ban restore skipped"
            );
            continue;
        };
        if let Err(e) = backend
            .ban_with_timeout(&ban.ip, &ban.jail_id, ban.expires_at, now)
            .await
        {
            warn!(
                ip = %ban.ip,
                jail = %ban.jail_id,
                error = %e,
                "ban restore failed"
            );
            continue;
        }
        restored.push(ban.clone());
    }
    restored
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::needless_pass_by_value
)]
#[path = "restore_test.rs"]
mod restore_test;
