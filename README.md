# fail2ban-rs

In ALPHA: We are running tests on this.

A modern Rust rewrite of [fail2ban](https://github.com/fail2ban/fail2ban).

fail2ban is a 20-year-old Python codebase that works, but requires a Python runtime on every production server, serializes all firewall operations behind a global thread lock, and executes shell commands via `subprocess.Popen(shell=True)`.

fail2ban-rs is a ground-up rewrite that eliminates all of that:

- **Single ~3MB binary** — no Python, no runtime, no interpreter startup overhead
- **Zero locks** — three async tasks connected by channels, single-owner state (Python fail2ban uses 9+ thread locks)
- **Two-phase matching** — Aho-Corasick pre-filter rejects non-matching lines before regex runs
- **No shell execution** — firewall backends call nft/iptables directly, no `shell=True`
- **6.6x faster startup** — 3.7ms vs 25.8ms (measured with hyperfine, 50 runs)
- **67% less code** — 4,200 lines of Rust vs 12,500 lines of Python

Everything else you'd expect: nftables/iptables/script backends, ban time escalation, config overlays, hot reload via SIGHUP, 19 built-in filters, systemd journal support.

## Install

```bash
curl -sSfL https://raw.githubusercontent.com/aejimmi/fail2ban-rs/main/scripts/install.sh | bash
```

Requires Linux, systemd, and root. Installs the binary, systemd service, and default config.

```bash
nano /etc/fail2ban-rs/config.toml    # edit config
systemctl start fail2ban-rs          # start
fail2ban-rs status                   # check status
journalctl -u fail2ban-rs -f         # logs
```

## Configuration

See `config/default.toml` for a full example.

```toml
[global]
state_file = "/var/lib/fail2ban-rs/state.bin"
socket_path = "/var/run/fail2ban-rs/fail2ban-rs.sock"
log_level = "info"

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

### Firewall backends

**nftables** (default): Creates table `inet fail2ban-rs`, chain, and per-jail sets. Teardown on shutdown.

**iptables**: Per-jail chains with multiport matching. Manages both `iptables` and `ip6tables`.

**script**: Custom commands with `<IP>` and `<JAIL>` placeholders:

```toml
[jail.custom.backend]
script = { ban_cmd = "/usr/local/bin/ban.sh <IP> <JAIL>", unban_cmd = "/usr/local/bin/unban.sh <IP> <JAIL>" }
```

### Config overlays

Additional `.toml` files in `config.d/` next to your main config are merged alphabetically.

## Built-in filters

`fail2ban-rs gen-config <name>` generates a jail config for any of these:

`sshd` `nginx-auth` `nginx-botsearch` `postfix` `dovecot` `vsftpd` `asterisk` `mysqld` `apache-auth` `apache-botsearch` `vaultwarden` `bitwarden` `proxmox` `gitlab` `grafana` `haproxy` `drupal` `traefik` `openvpn`

## CLI

```bash
fail2ban-rs status                              # show all jails and bans
fail2ban-rs ban 1.2.3.4 sshd                   # manually ban an IP
fail2ban-rs unban 1.2.3.4 sshd                 # manually unban
fail2ban-rs regex --pattern '...' --line '...'  # test a pattern
fail2ban-rs gen-config sshd                     # generate jail config
systemctl reload fail2ban-rs                    # hot reload (SIGHUP)
```

## Building from source

```bash
cargo build --release
cargo test
```

## Migration from fail2ban

| fail2ban | fail2ban-rs |
|---|---|
| `/etc/fail2ban/jail.conf` | `/etc/fail2ban-rs/config.toml` |
| `failregex = ...` | `filter = ['...']` |
| `maxretry = 5` | `max_retry = 5` |
| `findtime = 10m` | `find_time = "10m"` |
| `bantime = 1h` | `ban_time = "1h"` |
| `bantime.increment = true` | `bantime_increment = true` |
| `bantime.multipliers = 1 2 4 8` | `bantime_multipliers = [1, 2, 4, 8]` |
| `action = iptables[...]` | `backend = "iptables"` |
| `ignoreip = 127.0.0.1/8` | `ignoreip = ["127.0.0.1/8"]` |
| `fail2ban-client status` | `fail2ban-rs status` |
| `fail2ban-client set sshd banip 1.2.3.4` | `fail2ban-rs ban 1.2.3.4 sshd` |

## License

MIT
