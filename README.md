A ground-up Rust rewrite of [fail2ban](https://github.com/fail2ban/fail2ban) — **5x faster matching · 6.6x faster startup · single binary · zero database · zero locks**

Used in production at [tell.rs](https://tell.rs) to protect application endpoints.

fail2ban is a 20-year-old Python codebase that works, but requires a Python runtime on every production server, serializes all firewall operations behind a global thread lock, and executes shell commands via `subprocess.Popen(shell=True)`.

fail2ban-rs eliminates all of that:

- **Single ~3 MB binary** — no Python, no runtime, no interpreter startup overhead
- **~6 MB RSS in production** — constant memory regardless of log volume
- **Zero locks** — three-layer async pipeline connected by channels, single-owner state (Python fail2ban uses 9+ thread locks)
- **5x faster per-line matching** — Aho-Corasick pre-filter + AC-guided regex selection
- **No shell execution** — nftables/iptables backends exec directly via argv, no `shell=True` (script backend uses `sh -c` but substitutes only validated `IpAddr` values)
- **6.6x faster startup** — 3.7ms vs 25.8ms (measured with hyperfine, 50 runs)
- **Constant-size state** — flat binary snapshot of active bans only. No SQLite database growing on disk for years
- **~1 MB at 10K active bans** — ring buffers store 5 timestamps per IP, not matched log lines

Everything else you'd expect: nftables/iptables/script backends, ban time escalation, config overlays, hot reload via SIGHUP, 88 built-in filters, systemd journal support.

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

**ipset**: For large ban lists, [ipset](https://ipset.netfilter.org/) provides O(1) kernel-level lookups via hash sets. Use the script backend with `reban_on_restart = false` since ipset persists across service restarts:

```toml
[jail.sshd]
reban_on_restart = false

[jail.sshd.backend.script]
ban_cmd = "ipset add fail2ban-sshd <IP>"
unban_cmd = "ipset del fail2ban-sshd <IP>"
```

Create the set and firewall rule beforehand:

```bash
ipset create fail2ban-sshd hash:ip
iptables -I INPUT -m set --match-set fail2ban-sshd src -j DROP
```

> **Note:** ipset lives in kernel memory — it survives service restarts but not system reboots. For persistence across reboots, use `ipset save` / `ipset restore` in a systemd unit or set `reban_on_restart = true`.

### Webhooks

Set `webhook` on a jail to POST a JSON payload (IP, jail, ban time, timestamp) on every ban:

```toml
[jail.sshd]
webhook = "https://example.com/hooks/ban"
```

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
fail2ban-rs ban 1.2.3.4 sshd                    # manually ban an IP
fail2ban-rs unban 1.2.3.4 sshd                  # manually unban
fail2ban-rs dry-run /var/log/auth.log -j sshd   # analyze a log without banning
fail2ban-rs regex --pattern '...' --line '...'  # test a pattern
fail2ban-rs gen-config sshd                     # generate jail config
fail2ban-rs list-filters                        # list all 88 built-in filters
fail2ban-rs reload                              # hot reload via control socket
systemctl reload fail2ban-rs                    # hot reload via SIGHUP
```

## Testing

Test patterns and dry-run against real logs — without touching any firewall.

```bash
# verify a pattern extracts the right IP from a log line
fail2ban-rs regex --pattern 'sshd\[\d+\]: Failed password for .* from <HOST>' \
  --line 'sshd[1234]: Failed password for root from 10.0.0.1 port 22 ssh2'

# dry-run against a real log file — shows which IPs would be banned
fail2ban-rs dry-run /var/log/auth.log --jail sshd
```

## Performance

Per-line matching pipeline benchmarks (MacBook M4 Pro, criterion), comparing against Python fail2ban's equivalent regex engine. Line mix based on [openssh_2k.log](sample/openssh_2k.log) from [logpai/loghub](https://github.com/logpai/loghub) (~30% hits, ~70% near-misses):

| Stage | Rust | Python | Speedup |
|---|---|---|---|
| Full pipeline (openssh_2k mix) | ~147 ns/line | ~740 ns/line | **5x** |
| Pattern match — hit | 291-353 ns | 457-730 ns | 1.6-2.1x |
| Pattern match — miss (AC rejects) | 20-56 ns | 342-574 ns | 6-29x |
| Date parse (ISO 8601) | 7.6 ns | 165 ns | 22x |

Run benchmarks yourself:
```bash
cargo bench --bench matching                 # Rust (criterion)
python3 benches/bench_matching_fail2ban.py   # Python (timeit)
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
| `action = iptables[...]` / `banaction = ...` | `backend = "iptables"` or `backend = "nftables"` | `nftables` is the default. Use the `script` backend for a custom ban/unban command. |
| persistent external ban list | `reban_on_restart = false` | Suitable when the external backend retains its own bans, such as ipset. |
| `fail2ban-client status` | `fail2ban-rs status` | |
| `fail2ban-client set sshd banip 1.2.3.4` | `fail2ban-rs ban 1.2.3.4 sshd` | |

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
