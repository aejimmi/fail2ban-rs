# Changelog

## v1.5.5

Fix:
- firewall: nft, iptables and ipset are found on NixOS, where they live in the system profile instead of the usual system directories

## v1.5.4

New:
- logs: syslog-format timestamps are parsed about 12x faster, roughly halving the time spent per line on a typical auth.log
- logs: lines are decoded and split with SIMD, making a full dry run about 14% faster

Fix:
- logs: journal lines with a multi-byte character split across a read boundary are no longer corrupted
- banning: expired failure records and stale escalation counters are cleaned up every minute even under constant traffic, instead of piling up in memory
- firewall: output from firewall commands and ban scripts is memory-bounded, so a noisy script can no longer balloon the daemon; an oversized firewall listing skips that reconcile pass instead of being half-read
- docs: performance figures are measured against fail2ban itself, and manual ban and unban examples use the required --jail flag

## v1.5.3

Fix:
- banning: a ban that cannot be saved to disk is no longer applied to the firewall or counted, and a manual ban reports the error
- banning: unbans report success only after the firewall removed the address; a failed unban keeps its record and is retried after a minute instead of leaving the address blocked
- reload: success is reported only once the new configuration is in effect, and the daemon exits for a service restart if its ban pipeline has stopped
- reload: queued failures are delivered before log watchers restart, so none are skipped under load

## v1.5.2

New:
- logs: log files that don't exist yet are picked up once they appear, and journalctl is restarted if it exits, so a jail no longer stops detecting silently
- reload: log watchers hand over their read position, so failures written during a reload are counted exactly once
- cli: list-bans works with thousands of active bans instead of failing once the list passes 64 KiB
- cli: dry-run reads the log in a single pass with bounded memory, and lists IPs with equal counts in a stable order
- notifications: webhooks send at most 8 at a time with a bounded backlog, and response bodies are discarded
- firewall: every firewall command times out after 30 seconds, and hung commands, including background processes started by ban scripts, are killed
- firewall: iptables waits for the xtables lock instead of failing when another tool holds it

Fix:
- firewall: IPv6 bans on nftables go to the IPv6 set instead of failing
- firewall: nftables and iptables teardown remove their rules, so a port change no longer leaves the old port blocked and restarts no longer stack duplicate rules
- firewall: iptables and ipset refuse to start a jail when the rule that makes bans block traffic can't be installed, instead of running with no effect
- firewall: re-initializing iptables or ipset jails no longer stacks duplicate rules, and unban removes every copy
- reload: changing a jail's port or protocol rebuilds its firewall rules
- reload: a reload whose new firewall setup fails restores the previous one instead of leaving the jail unprotected
- reload: an IP unbanned while a reload is running is no longer banned again by it
- banning: manual bans report success only after the firewall applied them, and a hung firewall command no longer stalls the daemon
- banning: a failed automatic ban is withdrawn from the firewall instead of lingering unrecorded
- reconcile: nftables bans are recognized when a set holds several addresses, instead of being re-added every 5 minutes
- reconcile: script-backend ban commands are no longer re-run every 5 minutes
- reconcile: every active ban is eventually checked instead of only the first 1,000, with one firewall listing per jail instead of one per ban
- reconcile: a check can no longer restore a ban that was just removed
- logs: stopping a watcher under heavy load no longer hangs
- logs: a new log file is no longer counted twice when its first line is written
- logs: a multi-line journal message can no longer forge a matching line that gets another IP banned
- config: jail names whose firewall sets or chains would collide with another jail's are rejected at startup

## v1.5.1

- persistence: a crash during storage compaction can no longer lose a generation of already-recorded bans — the new snapshot is committed before the log is rotated
- persistence: the previous log is kept until a replacement snapshot is confirmed, so the recovery path survives a crash mid-compaction
- persistence: foreground and background compaction can no longer run at the same time and interleave
- security: the dependency tree is clear of known advisories — the unsound memory-mapping code behind GeoIP lookups is patched, and an unmaintained and a yanked crate are gone

## v1.5.0

New:
- firewall: native ipset backend via backend = "ipset" — bans become O(1) kernel hash lookups instead of a linear chain walk, with the sets and match rules created and torn down for you
- firewall: ipset bans carry a kernel-side timeout, so they expire even if the daemon dies
- firewall: ipset set capacity is tunable with maxelem, for jails that ban more than the 65536 default
- firewall: ipset match rules can target a chain other than INPUT, so Docker hosts can drop traffic to published container ports from DOCKER-USER
- config: a backend takes either a bare name or a settings table, so backend = "ipset" and [jail.sshd.backend.ipset] both work
- config: ipset jails are checked at startup for name length, set capacity, and chain name instead of failing later against the kernel
- reload: changing an ipset jail's maxelem or chain rebuilds the set, rather than silently keeping the old capacity
- docs: Spanish README
- docs: fail2ban migration guide covering config layout, jail keys, filters, date formats, and the commands with no direct equivalent

## v1.4.1

- persistence: upgraded the embedded storage engine (etchdb 0.5) with WAL crash-safety and durability fixes
- persistence: startup warns if any ban-state entries were unreadable and dropped during load, instead of loading a partial state silently

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
