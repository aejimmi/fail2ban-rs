A ground-up Rust rewrite of [fail2ban](https://github.com/fail2ban/fail2ban) — **single binary · async pipeline · embedded persistence**

Used in production at [tell.rs](https://tell.rs) to protect application endpoints.

fail2ban is a 20-year-old Python codebase that works, but requires a Python runtime on every production server, serializes all firewall operations behind a global thread lock, and executes shell commands via `subprocess.Popen(shell=True)`.

fail2ban-rs eliminates all of that:

- **Single ~5 MB binary** — no Python, no runtime, no interpreter startup overhead
- **~9 MB idle RSS** — RSS depends on configuration, tracked IPs, and active bans
- **Single-owner tracker** — bounded channels connect detection, tracking, and enforcement; persistence and some backends still use locks, and firewall commands run through one ordered executor
- **5x faster per-line matching in the synthetic Python `re` benchmark** — Aho-Corasick pre-filter + AC-guided regex selection
- **Direct native firewall execution** — nftables/iptables/ipset commands use argv; the script backend uses `sh -c` with validated IP and jail substitutions
- **~7x faster startup in the historical benchmark** — 3.7ms vs 25.8ms (reported with hyperfine, 50 runs)
- **Embedded EtchDB state** — WAL and compacted snapshots store active bans, escalation counters, and metadata without SQLite; disk usage grows with retained state
- **40 bytes of timestamps per tracked IP/jail by default** — ring buffers store 5 timestamps per IP, not matched log lines; excludes other state and overhead

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

**ipset**: For large ban lists, [ipset](https://ipset.netfilter.org/) turns every ban into an O(1) kernel hash lookup instead of a linear walk down a chain. Nothing to prepare by hand:

```toml
[jail.sshd]
backend = "ipset"
```

That is the whole configuration. The jail gets two `hash:ip` sets — `f2b-sshd` for IPv4 and `f2b-sshd6` for IPv6 — plus one `-m set --match-set ... -j DROP` rule per family in `INPUT`, scoped to the jail's `port`/`protocol` when set. Each ban carries a kernel-side timeout, so it self-clears even if the daemon dies. Teardown removes the rules, then flushes and destroys the sets.

Two optional knobs:

```toml
[jail.sshd.backend.ipset]
maxelem = 200000       # max entries per set (default 65536)
chain = "DOCKER-USER"  # chain the match rule goes into (default INPUT)
```

`chain` earns its keep on Docker hosts: traffic to published container ports bypasses `INPUT`, so the DROP rule has to sit in `DOCKER-USER` to ever see those packets.

Needs the `ipset` tool and the `ip_set`, `ip_set_hash_ip`, and `xt_set` kernel modules alongside `iptables`/`ip6tables`.

> **Note:** leave `reban_on_restart` at its `true` default. fail2ban-rs owns these sets and destroys them on a clean shutdown, so bans come back from the WAL at startup — and adding an entry that is already there is a no-op, so a reban costs nothing when the set did survive.

Two limits worth knowing: a jail on this backend needs a name of at most 26 characters, since `f2b-<jail>6` must fit ipset's 31-character cap, and `maxelem` bounds the ban list. A full set rejects further bans — they fail loudly and the IP is retried rather than recorded as banned — so raise `maxelem` for busy jails, at the cost of kernel memory.

**Firewall persistence and retries.** A ban is written to the WAL before it reaches the firewall, and an unban keeps its record until the firewall confirms removal — a failed unban retries after 60 seconds instead of leaving the address blocked. Every firewall command is killed after 30 seconds, including background processes a ban script leaves behind. iptables waits for the xtables lock rather than failing when another tool holds it. Every 5 minutes the daemon schedules a reconciliation batch of up to 1,000 active bans. Native backends list each jail's firewall state and re-apply missing bans; a complete pass over larger ban lists takes multiple batches. The script backend cannot verify external firewall state and skips this check.

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
fail2ban-rs ban 1.2.3.4 --jail sshd              # manually ban an IP
fail2ban-rs unban 1.2.3.4 --jail sshd            # manually unban
fail2ban-rs dry-run /var/log/auth.log -j sshd   # analyze a log without banning
fail2ban-rs regex --pattern '...' --line '...'  # test a pattern
fail2ban-rs gen-config sshd                     # generate jail config
fail2ban-rs list-filters                        # list all 88 built-in filters
fail2ban-rs reload                              # hot reload via control socket
systemctl reload fail2ban-rs                    # hot reload via SIGHUP
```

`ban` and `unban` return only after the firewall applied the change; a firewall error comes back as an error, not a false success. Reload hands each log watcher's read position to its replacement and drains queued failures first, so a failure written during the reload is counted exactly once. Port or protocol changes rebuild the jail's rules, a failed firewall setup restores the previous one, and success is reported only once the daemon has applied the new config.

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

Historical matching microbenchmarks (MacBook M4 Pro, Criterion for Rust, `timeit` for Python `re`, not fail2ban's filter engine). Synthetic ten-line mix based on [openssh_2k.log](sample/openssh_2k.log) from [logpai/loghub](https://github.com/logpai/loghub) (~30% hits, ~70% near-misses):

| Stage | Rust | Python | Speedup |
|---|---|---|---|
| Date + matching (synthetic mix) | ~147 ns/line | ~740 ns/line | **5x** |
| Pattern match — hit | 291-353 ns | 457-730 ns | 1.6-2.1x |
| Pattern match — miss (AC rejects) | 20-56 ns | 342-574 ns | 6-29x |
| Date parse (ISO 8601) | 7.6 ns | 165 ns | Not comparable |

Timings depend on the workload and machine and exclude daemon ingestion, tracking, persistence, and firewall execution. Python's date benchmark only searches a regex; Rust converts to a timestamp, so the date timings are not comparable.

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
