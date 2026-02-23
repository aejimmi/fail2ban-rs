# Changelog

## v1.0.0 

fail2ban-rs runs in production

New:
- cli: list-bans outputs a human-readable table sorted by expiry with relative time remaining
- cli: list-bans --json flag for JSONL output with jail-first field ordering

## v0.1.3

- cli: dry-run output shows jail config, threshold, ban count, and per-IP remaining failures
- cli: regex tool explains match results and gives hints on no-match
- readme: testing before production section with regex and dry-run examples

## v0.1.2

New:
- executor: resolve nft/iptables/ip6tables to absolute paths at startup, preventing PATH hijack
- benches: line mix updated to 30/70 hit/miss ratio based on openssh_2k.log from logpai/loghub
- sample: openssh_2k.log added as reference dataset for benchmark calibration

Fix:
- readme: pipeline speedup corrected from 3.2x to 5x using realistic log distribution
- readme: shell execution claim clarified to note script backend uses sh -c with validated IpAddr
- executor: script backend documents safety invariant for sh -c substitution

## v0.1.1

New:
- matcher: AC-guided regex selection replaces RegexSet, skips impossible patterns via deduplicated prefix mapping
- matcher: token-scan IP extraction using find() instead of captures(), avoids PikeVM overhead
- date: zero-alloc byte scanner for ISO 8601 replaces regex + chrono
- state: xxh3_64 integrity checksum replaces crc32, reuses existing xxhash dep
- config: jail name, port, protocol, and bantime_factor validation
- security: input fuzzing test suite covering injection, spoofing, overflow, and ReDoS vectors
- benches: criterion benchmark suite for matching pipeline with Python fail2ban comparison script
- readme: performance benchmarks section with per-stage ns/line measurements

Fix:
- control: restrict Unix socket and parent directory permissions to owner+group
- executor: exact token matching for is_banned checks in iptables and nftables backends
- duration: checked multiplication prevents overflow on large duration values
- pattern: prefer longer literal prefixes for better AC selectivity

Infra:
- deps: drop crc32fast, add criterion as dev-dependency

Breaking:
- state: format bumped to v3 (xxh3_64 checksum), v1/v2 state files must be discarded
