# Changelog

## v1.4.0

New:
- banning: repeat-offender escalation resets after a quiet period, configurable via ban_count_decay (default 30 days, 0 disables)
- firewall: nftables entries carry kernel timeouts so bans expire even if the daemon dies
- firewall: bans missing from the firewall are re-applied automatically, and bans that fail to apply are rolled back instead of lingering as phantom state
- config: unknown or misspelled keys rejected at load instead of silently getting defaults
- config: startup validation catches invalid ignoreip entries, filter regexes, ports, ban times, webhook URLs, and zero channel sizes
- config: ignoreip accepts bare IPs without a CIDR suffix
- security: control socket verifies the connecting user on Linux and caps oversized responses

Fix:
- startup: persisted bans are restored after firewall setup, so bans actually survive a restart again
- reload: banned IPs stay blocked through a config reload; jails are updated in place instead of torn down and rebuilt
- banning: an unbanned IP must reach the full failure threshold again before being re-banned
- banning: a re-banned IP is no longer unbanned early by a leftover timer from its previous ban
- banning: manual bans use the jail's configured ban time instead of a fixed hour
- date: timezone offsets in log timestamps are applied, syslog times are read as local time, and the New Year rollover is handled
- watcher: lines written in multiple chunks are matched whole, and log rotation no longer drops the last lines of the old file
- notifications: webhook URLs restricted to http and https and passed safely to curl
- firewall: a failing nft query is reported as an error instead of "not banned"
- logging: the old global.log_level key is now honored with a deprecation warning, as v1.3.0 promised
- cli: dry-run applies the find_time window so its verdicts match the running daemon

Breaking:
- persistence: ban state format changed; old state is preserved as a .bak file but active bans are not restored across this upgrade
- config: stricter validation can reject files that previously loaded; error messages name the offending key or value

## v1.3.0

New:
- logging: native journald output with correct syslog severity, structured fields, and no duplicate timestamps
- logging: logfmt (default) or json output format
- logging: severity level moved to logging.level, old global.log_level still accepted

Fix:
- logging: journalctl severity filtering and color-coding now work per-line
- logging: no duplicate fields in journald metadata, no double-rendering on stderr
- logging: service name taken from the systemd unit identifier

## v1.2.3

Fix:
- reload: active bans preserved across config reload, with rollback on failure (thanks @miniers)
- shutdown: daemon responds to SIGTERM for clean systemctl stop (thanks @miniers)
- config: systemd journal backend no longer requires a dummy log_path (thanks @miniers)

## v1.2.2

- fix: build Linux release binaries with musl for glibc compatibility

## v1.2.1

- fix(detect/journal): resolve double mutable borrow, drop systemd feature flag
- installer: no longer attempts to delete the system temp directory when run on an unsupported OS
- installer: non-Linux systems get a clear unsupported-OS error before the root check

## v1.2.0

New:
- geo: country, city, and ASN info on ban events using local MaxMind databases
- geo: invalid field names rejected at startup instead of silently ignored
- geo: list-maxmind command shows database paths and load status
- geo: can be disabled at compile time
- jails: state_file renamed to state_dir, old name still works
- jails: per-jail option to skip re-banning on restart when firewall rules already exist
- jails: macOS development config for rootless testing
- persistence: write-ahead-log storage for safer crash recovery
- persistence: bans saved immediately instead of every 60 seconds
- startup: expired bans cleaned up instead of being restored
- security: systemd service hardened with capability, filesystem, and syscall restrictions
- journal: oversized lines bounded to 64 KB to match file watcher
- matching: positional IP extraction picks the correct host when other IPs appear in URLs or log fields
- filters: 88 built-in filter templates covering sshd, nginx, apache, postfix, dovecot, vaultwarden, grafana, and dozens more
- cli: gen-config and list-filters use the expanded filter library
- matching: AC-guided regex selection only tries patterns whose literal prefix appears in the line
- matching: ignoreregex patterns suppress lines even when a failregex matches
- date: ISO 8601 parser uses zero-alloc byte scanning instead of regex

Fix:
- watcher: log files with invalid UTF-8 bytes no longer stop the daemon from processing further lines
- security: control socket rejects ban and unban requests for unknown jails
- geo: world-writable MaxMind databases refused at startup instead of warned
- logging: clean output when piped or redirected, logs written to stderr
- matching: IPs inside brackets now detected correctly in postfix-style logs

Breaking:
- persistence: old state.bin files backed up automatically, new storage format used

## v1.0.0

fail2ban-rs runs in production

New:
- bans: list-bans outputs a sorted table with relative time remaining
- bans: list-bans supports JSON output

## v0.1.3

- testing: dry-run shows jail config, threshold, ban count, and per-IP remaining failures
- testing: regex tool explains match results and gives hints on no-match

## v0.1.2

- security: firewall commands resolved to absolute paths to prevent PATH hijack

## v0.1.1

New:
- matching: faster log matching using pattern pre-filtering
- matching: faster IP extraction from log lines
- matching: faster timestamp parsing with lower memory use
- jails: settings validated at startup with clear error messages

Fix:
- security: control socket locked to owner and group only
- bans: exact IP matching prevents false positives on substring matches
- jails: large ban durations no longer overflow

Breaking:
- persistence: file format changed, old state files must be discarded
