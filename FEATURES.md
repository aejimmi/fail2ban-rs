# Features

## Matching

- Two-phase log matching — Aho-Corasick pre-filter rejects non-matching lines in nanoseconds, then only tries relevant regexes.
- Positional IP extraction — identifies the correct host IP by its position in the pattern, even when other IPs appear in URLs or log fields.
- Ignore regex — lines matching ignoreregex are suppressed even when a failregex matches.
- Four timestamp formats — syslog and ISO 8601 (zero-alloc byte scanners), unix epoch, and common log format.
- Timezone-aware parsing — numeric `+HHMM`/`-HHMM` offsets are normalized to UTC; ambiguous or skipped local times (DST transitions) resolve deterministically.

## Banning

- Configurable thresholds — max retries, find time window, and ban duration per jail.
- Escalating bans — repeat offenders get progressively longer bans with configurable multipliers and a maximum cap.
- Escalation decay — per-IP ban counts reset after a configurable quiet period (`ban_count_decay`, default 30d; `"0"` disables), bounding memory and giving reformed IPs a clean slate.
- Permanent bans — set ban time to -1 for indefinite bans.
- IP allowlist — never ban IPs or CIDRs in the ignore list; auto-detects local machine IPs by default.
- Manual ban and unban — issue bans and unbans via CLI for any jail; the command returns only after the firewall applied the change, and a firewall error is reported instead of a false success.

## Firewall

- nftables backend — creates per-jail chains and IP sets.
- iptables backend — per-jail chains with individual rules.
- ipset backend — per-jail hash:ip sets behind one match rule per address family, giving O(1) kernel lookups on large ban lists; sets and rules are created and destroyed by the daemon.
- Kernel-side ban timeouts — ipset entries expire on their own, so a dead daemon cannot leave a permanent ban.
- Tunable ipset capacity and chain — maxelem sizes the set, chain places the drop rule outside INPUT for Docker hosts.
- Script backend — user-defined ban and unban shell commands for custom firewalls.
- Absolute path resolution — firewall commands resolved to full paths to prevent PATH hijack.
- Bounded command output — output from firewall commands and ban scripts is capped in memory, so a noisy script cannot balloon the daemon.
- Reconcile — every 5 minutes active bans are checked against the firewall and missing ones re-applied, rotating through the whole list with one listing per jail rather than one command per ban.
- Command timeout — every firewall command is killed after 30 seconds, including background processes started by ban scripts, so a hung tool cannot stall the daemon; iptables waits for the xtables lock rather than failing when another tool holds it.

## Persistence

- WAL-backed storage — bans persisted immediately via write-ahead log for crash recovery.
- Persist before apply — a ban is written to the log before it reaches the firewall, and a ban the firewall rejects is withdrawn again, so state and firewall never disagree about who is banned.
- Confirmed unbans — a ban record survives until the firewall confirms removal; a failed or hung unban keeps the record, retries after 60 seconds, and triggers a jail reconcile.
- Ordered restore — firewall chains and sets are initialized before any saved ban is re-applied, so restored bans are never dropped after a clean restart.
- Expired ban cleanup — stale bans purged on startup instead of being restored.
- Automatic migration — old state.bin files and schema-incompatible WALs are backed up aside and a fresh store is opened, rather than silently misreading stale bytes.

## Log Sources

- File watcher — tails log files, detects rotation via inode/size/hash, and reopens automatically.
- Systemd journal — reads from journald with configurable match filters per jail.
- Invalid UTF-8 tolerance — lines with encoding errors are skipped without stopping the watcher.
- Line size limit — lines over 64 KB are bounded in both file and journal watchers.
- Late log files — a log that does not exist yet is picked up with backoff once it appears, so a jail never stops detecting silently.
- Journal supervision — journalctl is restarted from its last cursor if it exits, with capped backoff.

## GeoIP

- MaxMind lookup — country, city, and ASN info on ban events using local GeoLite2 databases.
- Per-jail field selection — choose which databases to query (asn, country, city) per jail.
- Startup validation — invalid field names rejected, world-writable database files refused.
- Compile-time opt-out — GeoIP can be disabled entirely at build time.

## CLI

- Status, stats, list-bans — query the running daemon via Unix socket.
- List-bans table and JSON — sorted table with relative time remaining, or JSONL output; works with thousands of active bans.
- Dry-run — analyze a log file without banning, showing jail config, thresholds, and per-IP failure counts; single pass with bounded memory and stable ordering for equal counts.
- Regex tester — test a pattern against a log line with match explanation and hints on failure.
- Config generator — generate jail TOML for 88 built-in services (sshd, nginx, apache, postfix, dovecot, vaultwarden, grafana, and more).
- List-filters — show all 88 available built-in filter templates.
- List-maxmind — show configured MaxMind database paths and load status.
- Live reload — reload configuration without restarting the daemon; jails are added or removed in place, port or protocol changes rebuild their rules, active bans are preserved, a failed firewall setup restores the previous one, and success means the new config is applied, not just received.
- Gap-free reload — log watchers hand over their read position and drain queued failures before replacements start, so every failure written during a reload is counted exactly once.

## Configuration

- TOML config — single config file with global settings and per-jail sections.
- Duration strings — ban_time, find_time accept human-readable values like "10m", "1h", "7d".
- Startup validation — jail names, ports, protocols, ban factors, filter regexes, ignoreip entries, and webhook URLs validated before the daemon starts.
- Unknown-key rejection — mistyped or unsupported config keys fail loudly at load instead of being silently ignored.
- Backward-compatible renames — state_file still works as an alias for state_dir.
- Per-jail reban control — skip re-issuing bans on restart when firewall state persists independently.

## Notifications

- Webhook — POST JSON to a URL on every ban event with IP, jail, ban time, and timestamp.
- Bounded delivery — at most 8 webhooks in flight with a backlog of 64, a 15 second timeout per delivery, and response bodies discarded, so a slow endpoint cannot back up the daemon.
- Remote logging — structured log forwarding via the Tell SDK.

## Logging

- Native journald output — per-line syslog severity, structured fields, no duplicate timestamps; works correctly with journalctl severity filtering and color-coding.
- Output format — logfmt (default) or JSON, configurable via the [logging] format option.
- Configurable severity threshold via [logging] level; legacy global.log_level still accepted.
- Stderr fallback — when the journal socket is unavailable, logs go to stderr without double-rendering.

## Deployment

- Single static binary — no runtime dependencies beyond the firewall tooling, plus `curl` on `PATH` only for jails that configure a webhook.
- Clean shutdown — responds to both SIGINT and SIGTERM, tearing down firewall rules before exit.
- Supervised exit — if the ban pipeline stops, the daemon exits nonzero so the shipped unit's Restart=on-failure brings it back instead of running blind.
- Systemd hardening — service unit with capability, filesystem, and syscall restrictions.
- macOS development config — rootless testing without firewall privileges.
