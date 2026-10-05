A ground-up Rust rewrite of [fail2ban](https://github.com/fail2ban/fail2ban) — **50x faster matching · 9x faster startup · single ~5 MB binary**

Used in production at [tell.rs](https://tell.rs) to protect application endpoints.

fail2ban is a 20-year-old Python codebase that works, but requires a Python runtime on every production server, serializes all firewall operations behind a global thread lock, and executes shell commands via `subprocess.Popen(shell=True)`.

fail2ban-rs is one static binary:

- **50x faster matching** — 158 ns per log line against 8,123 ns for fail2ban, on the same log with the same patterns
- **9x faster startup** — 4 ms against 38 ms
- **~5 MB binary, ~9 MB idle memory** — no Python, no runtime, no interpreter
- **Nothing to maintain** — bans persist in an embedded write-ahead log and survive restarts and crashes; no SQLite database growing on disk
- **No shell for native firewalls** — nftables, iptables, and ipset commands run directly via argv

Everything else you'd expect: nftables/iptables/ipset/script backends, ban time escalation, config overlays, hot reload via SIGHUP, 88 built-in filters, systemd journal support.

## Install

Requires Linux and systemd. Installs the binary, systemd service, and default config.

```bash
curl -sSfL https://raw.githubusercontent.com/aejimmi/fail2ban-rs/main/scripts/install.sh | bash
```

Or install just the binary from crates.io:

```bash
cargo install fail2ban-rs
```

```bash
vi /etc/fail2ban-rs/config.toml       # edit config
systemctl enable fail2ban-rs          # start on boot
systemctl start fail2ban-rs           # start
fail2ban-rs status                    # check status
journalctl -u fail2ban-rs -f          # logs
```

## Configuration

See [`config/default.toml`](config/default.toml) for all options. Minimal jail:

```toml
[jail.sshd]
enabled = true
log_path = "/var/log/auth.log"
date_format = "syslog"
filter = [
    'sshd\[\d+\]: Failed password for .* from <HOST>',
    'sshd\[\d+\]: Invalid user .* from <HOST>',
]
port = ["22"]
protocol = "tcp"
max_retry = 5
find_time = "10m"
ban_time = "1h"
backend = "nftables"

# Ban time escalation for repeat offenders
bantime_increment = true
bantime_multipliers = [1, 2, 4, 8, 16, 32, 64]
bantime_maxtime = "1w"

# IPs/CIDRs to never ban
ignoreip = ["127.0.0.1/8", "::1/128"]
ignoreself = true
```

Durations accept `s`, `m`, `h`, `d`, `w` suffixes (e.g. `"10m"`, `"1h"`, `"7d"`). Raw seconds also work.

### Escalation decay

With `bantime_increment`, each repeat ban of an IP raises its ban time. The per-IP escalation counter is reset after a quiet period so a reformed IP starts fresh and the counter map cannot grow without bound:

```toml
[global]
ban_count_decay = "30d"   # reset escalation count after 30 quiet days (default); "0" disables
```

An IP with no new ban within `ban_count_decay` has its escalation count dropped on the next sweep, so its next offense escalates from zero again — mirroring fail2ban's bantime-decay concept.

### Firewall backends

**nftables** (default): Creates table `inet fail2ban-rs`, chain, and per-jail sets. Teardown on shutdown.

**iptables**: Per-jail chains with multiport matching. Manages both `iptables` and `ip6tables`.

**script**: Custom commands with `<IP>` and `<JAIL>` placeholders:

```toml
[jail.custom.backend.script]
ban_cmd = "/usr/local/bin/ban.sh <IP> <JAIL>"
unban_cmd = "/usr/local/bin/unban.sh <IP> <JAIL>"
```

**ipset**: For large ban lists. Every ban becomes an O(1) kernel hash lookup instead of a linear walk down a chain, and there is nothing to prepare by hand:

```toml
[jail.sshd]
backend = "ipset"
```

The daemon creates and destroys the sets and match rules itself. Each ban carries a kernel-side timeout, so it clears even if the daemon dies. Two optional knobs:

```toml
[jail.sshd.backend.ipset]
maxelem = 200000       # max entries per set (default 65536)
chain = "DOCKER-USER"  # chain for the match rule (default INPUT); needed for published Docker ports
```

Needs the `ipset` tool and the `ip_set`, `ip_set_hash_ip`, and `xt_set` kernel modules alongside `iptables`/`ip6tables`. Jail names are limited to 26 characters, and a full set rejects further bans, so raise `maxelem` for busy jails. Leave `reban_on_restart` at its `true` default.

All backends share these guarantees:

- **Durable bans** — a ban is written to disk before it reaches the firewall, and an unban keeps its record until the firewall confirms removal, retrying after 60 seconds on failure.
- **No hung commands** — every firewall command is killed after 30 seconds, including background processes a ban script leaves behind.
- **Self-healing** — every 5 minutes up to 1,000 active bans are checked against the firewall and missing ones are re-applied. The script backend cannot be verified and is skipped.

### Webhooks

Set `webhook` on a jail to POST a JSON payload (IP, jail, ban time, timestamp) on every ban:

```toml
[jail.sshd]
webhook = "https://example.com/hooks/ban"
```

Delivery is bounded: at most 8 requests in flight, a backlog of 64, a 15 second timeout per request, and the response body is discarded. A slow endpoint drops notifications; it never backs up banning.

> **Note:** webhooks shell out to `curl` on `PATH` — the one dependency beyond the firewall tooling that the single-binary install doesn't bundle. Jails without a `webhook` never invoke it.

### Config overlays

Additional `.toml` files in `config.d/` next to your main config are merged alphabetically.

Unknown keys are rejected at load, so a typo fails fast instead of being silently ignored.

## Built-in filters

`fail2ban-rs gen-config <name>` generates a jail config for any of **88 built-in services**, including:

`sshd` `nginx-auth` `nginx-botsearch` `postfix` `dovecot` `vsftpd` `asterisk` `mysqld` `apache-auth` `apache-botsearch` `vaultwarden` `bitwarden` `proxmox` `gitlab` `grafana` `haproxy` `drupal` `traefik` `openvpn`

Run `fail2ban-rs list-filters` for the full list.

## CLI

```bash
fail2ban-rs status                              # show all jails and bans
fail2ban-rs list-bans                           # sorted table of active bans (--json for JSONL)
fail2ban-rs stats                               # daemon statistics
fail2ban-rs ban 1.2.3.4 --jail sshd             # manually ban an IP
fail2ban-rs unban 1.2.3.4 --jail sshd           # manually unban
fail2ban-rs dry-run /var/log/auth.log -j sshd   # analyze a log without banning
fail2ban-rs regex --pattern '...' --line '...'  # test a pattern
fail2ban-rs gen-config sshd                     # generate jail config
fail2ban-rs list-filters                        # list all 88 built-in filters
fail2ban-rs reload                              # hot reload via control socket
systemctl reload fail2ban-rs                    # hot reload via SIGHUP
```

`ban` and `unban` return only after the firewall applied the change. A reload counts every failure written during it exactly once and reports success only once the new config is applied. `regex` and `dry-run` never touch the firewall, so patterns can be tested against real logs safely.

## Performance

Measured against fail2ban 1.1.0 on the same machine (MacBook M4 Pro), with the same log, the same patterns, and identical match counts:

| | fail2ban-rs | fail2ban | |
|---|---|---|---|
| Matching, per log line | 158 ns | 8,123 ns | **50x** |
| Startup | 4 ms | 38 ms | **9x** |

Matching is timed over 200,000 lines of [openssh_2k.log](sample/openssh_2k.log) from [logpai/loghub](https://github.com/logpai/loghub), with startup time subtracted. Startup is `--version` of each tool. Reproduce it:

```bash
fail2ban-rs dry-run auth.log --jail sshd              # fail2ban-rs
fail2ban-regex --no-check-all auth.log filter.conf    # fail2ban
cargo bench --bench matching                          # per-stage microbenchmarks
```

## Building from source

```bash
cargo build --release
cargo test
```

## Migration from fail2ban

fail2ban-rs does not read fail2ban's INI files directly. Create a TOML
`[jail.<name>]` table for each enabled fail2ban jail. `config.d/*.toml` files,
merged alphabetically after the main configuration, are the closest equivalent
to `jail.d/*.local` overrides.

| fail2ban | fail2ban-rs | Notes |
|---|---|---|
| `/etc/fail2ban/jail.conf`, `jail.local` | `/etc/fail2ban-rs/config.toml` | Use `[jail.sshd]`, not `[sshd]`. |
| `jail.d/*.local` | `/etc/fail2ban-rs/config.d/*.toml` | Later files override earlier values. |
| `enabled = true` | `enabled = true` | Enabled defaults to `true` in a TOML jail. |
| `logpath = /var/log/auth.log` | `log_path = "/var/log/auth.log"` | One file per jail; fail2ban glob and multi-file `logpath` values need separate jails. |
| `backend = systemd` | `log_backend = "systemd"` | Omit `log_path` and add `journalmatch = ["_SYSTEMD_UNIT=sshd.service"]` as needed. File watching is `log_backend = "file"`. |
| `journalmatch = ...` | `journalmatch = ["..."]` | One journal field-match expression per array entry. |
| `datepattern = ...` | `date_format = "syslog"` | Choose one preset: `syslog`, `iso8601`, `epoch`, or `common`; arbitrary fail2ban `datepattern` expressions are not supported. |
| `filter = sshd` / `failregex = ...` | `filter = ['... <HOST> ...']` | Copy the actual patterns, with exactly one `<HOST>` per pattern. Use `gen-config` to start from a built-in template. |
| `ignoreregex = ...` | `ignoreregex = ['...']` | Each matching line is suppressed even if it matches `filter`. These are Rust regular expressions; `<HOST>` is not expanded here. |
| `maxretry = 5` | `max_retry = 5` | |
| `findtime = 10m` | `find_time = "10m"` | Numeric seconds also work. |
| `bantime = 1h` | `ban_time = "1h"` | Use `-1` for a permanent ban. |
| `bantime.increment = true` | `bantime_increment = true` | |
| `bantime.factor = 1` | `bantime_factor = 1.0` | |
| `bantime.multipliers = 1 2 4 8` | `bantime_multipliers = [1, 2, 4, 8]` | |
| `bantime.maxtime = 1w` | `bantime_maxtime = "1w"` | |
| `ignoreip = 127.0.0.1/8 ::1` | `ignoreip = ["127.0.0.1/8", "::1"]` | IP addresses and CIDRs only; DNS hostnames are not resolved. |
| `ignoreself = true` | `ignoreself = true` | |
| `port = 22`, `protocol = tcp` | `port = ["22"]`, `protocol = "tcp"` | Ports must be numeric; translate service names, ranges, and multiport expressions first. |
| `action = iptables[...]` / `banaction = ...` | `backend = "iptables"`, `"nftables"`, or `"ipset"` | `nftables` is the default. Use the `script` backend for a custom ban/unban command. |
| `banaction = iptables-ipset-proto6[...]` | `backend = "ipset"` | Native — sets and match rules are auto-created, no `[Init]` section needed. Leave `reban_on_restart` at its `true` default. |
| persistent external ban list | `reban_on_restart = false` | Only for `script` backends whose external store keeps bans on its own; the native ipset backend rebans from state instead. |
| `fail2ban-client status` | `fail2ban-rs status` | |
| `fail2ban-client set sshd banip 1.2.3.4` | `fail2ban-rs ban 1.2.3.4 --jail sshd` | |

The following fail2ban features have no direct configuration equivalent yet:
custom filter tags and interpolation (`%(...)s`), `prefregex`, `maxlines`,
arbitrary `datepattern`, DNS-based `ignoreip`/`usedns`, `ignorecommand`,
`bantime.rndtime`, `bantime.formula`, `bantime.overalljails`, named or ranged
ports, multiple file/glob log paths, and fail2ban action definitions (email,
Cloudflare, reporting, and multiple actions). A jail using these needs a
simplified filter/configuration, separate jails, or a `script` backend.

## Roadmap

- Recidive — repeat offenders auto-escalate to longer, all-port bans across jails
- Ban actions — pluggable post-ban hooks for AbuseIPDB, Cloudflare edge blocking, and notifications
- IP enrichment — whois, reverse DNS, and X-ARF abuse reports on ban events
- BSD firewalls — pf and ipfw backends for OpenBSD/FreeBSD
- Threat feed blocking — import blocklists to block known attackers proactively
- Cross-server ban sharing — one node's ban propagates across the cluster
- Distribution packages — apt, RPM, Homebrew, AUR

[Sponsoring](https://github.com/sponsors/aejimmi) helps prioritize these.

## License

MIT
