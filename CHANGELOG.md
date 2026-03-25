# Changelog

## v1.1.0

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

Fix:
- logging: clean output when piped or redirected, logs written to stderr
- matching: IPs inside brackets now detected correctly in postfix-style logs
- geo: database files validated before loading, warns on unsafe permissions

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
