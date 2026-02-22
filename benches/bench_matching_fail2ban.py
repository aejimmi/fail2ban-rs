#!/usr/bin/env python3
"""
Equivalent matching benchmark in Python — for comparison with fail2ban-rs.

Uses the same sshd regex patterns and the same log line patterns.
This mirrors what fail2ban's filter engine does internally: loop over
compiled regexes, call re.search(), extract the IP.

Usage:
    python3 compare/bench_matching.py
"""

import re
import timeit

# ---------------------------------------------------------------------------
# Same sshd patterns as fail2ban-rs filters.rs, translated to Python regex.
# <HOST> is expanded to the same capture group.
# ---------------------------------------------------------------------------

HOST_RE = r"(?P<host>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[0-9a-fA-F:]{2,39})"

SSHD_PATTERNS = [
    re.compile(r'sshd\[\d+\]: Failed password for .* from ' + HOST_RE + r' port \d+'),
    re.compile(r'sshd\[\d+\]: Invalid user .* from ' + HOST_RE + r' port \d+'),
    re.compile(r'sshd\[\d+\]: Connection closed by authenticating user .* ' + HOST_RE + r' port \d+'),
    re.compile(r'sshd\[\d+\]: Disconnected from authenticating user .* ' + HOST_RE + r' port \d+'),
]

# ISO 8601 date regex (same as fail2ban-rs date.rs)
DATE_RE = re.compile(r'(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})')

# ---------------------------------------------------------------------------
# Same real log line patterns
# ---------------------------------------------------------------------------

HIT_INVALID_USER = (
    "2026-02-15T00:01:46.515991+00:00 api "
    "sshd[203661]: Invalid user banxgg from 80.94.92.184 port 55708"
)

HIT_CONN_CLOSED_AUTH = (
    "2026-02-15T00:00:36.396434+00:00 api "
    "sshd[203657]: Connection closed by authenticating user root "
    "103.174.103.249 port 58414 [preauth]"
)

MISS_CRON = (
    "2026-02-15T00:05:01.699457+00:00 api "
    "CRON[203684]: pam_unix(cron:session): session opened for user "
    "root(uid=0) by root(uid=0)"
)

MISS_CONN_CLOSED_INVALID = (
    "2026-02-15T00:01:46.694556+00:00 api "
    "sshd[203661]: Connection closed by invalid user banxgg 80.94.92.184 "
    "port 55708 [preauth]"
)

MISS_CONN_RESET = (
    "2026-02-15T00:11:49.416926+00:00 api "
    "sshd[203717]: Connection reset by authenticating user root "
    "176.120.22.47 port 27094 [preauth]"
)


def try_match(line: str):
    """Equivalent to JailMatcher::try_match() — what fail2ban does per line."""
    for regex in SSHD_PATTERNS:
        m = regex.search(line)
        if m:
            return m.group("host")
    return None


def parse_date(line: str):
    """Equivalent to DateParser::parse_line()."""
    return DATE_RE.search(line)


def pipeline(line: str):
    """Date parse + pattern match — the full hot path."""
    parse_date(line)
    return try_match(line)


def bench_one(label: str, func, line: str, iterations: int = 500_000):
    """Time a single function call and report ns/call."""
    elapsed = timeit.timeit(lambda: func(line), number=iterations)
    ns_per_call = (elapsed / iterations) * 1e9
    result = func(line)
    status = f"-> {result}" if result else "-> None"
    print(f"  {label:30s} {ns_per_call:8.0f} ns/call  {status}")


def main():
    n = 500_000
    print(f"\nPython sshd matching benchmark ({n:,} iterations each)")
    print("=" * 70)

    print("\ntry_match (pattern matching only):")
    bench_one("hit_invalid_user", try_match, HIT_INVALID_USER, n)
    bench_one("hit_conn_closed_auth", try_match, HIT_CONN_CLOSED_AUTH, n)
    bench_one("miss_cron", try_match, MISS_CRON, n)
    bench_one("miss_near_invalid_user", try_match, MISS_CONN_CLOSED_INVALID, n)
    bench_one("miss_near_conn_reset", try_match, MISS_CONN_RESET, n)

    print("\ndate_parse (ISO 8601):")
    bench_one("iso8601", parse_date, HIT_INVALID_USER, n)

    print("\npipeline (date + match):")
    bench_one("hit_invalid_user", pipeline, HIT_INVALID_USER, n)
    bench_one("miss_cron", pipeline, MISS_CRON, n)

    # Mixed workload — same ratio as the Rust benchmark.
    # ~30% hits, ~70% near-misses — mirrors openssh_2k.log (logpai/loghub).
    lines = [
        HIT_CONN_CLOSED_AUTH,
        HIT_INVALID_USER,
        HIT_CONN_CLOSED_AUTH,
        MISS_CONN_CLOSED_INVALID,
        MISS_CONN_CLOSED_INVALID,
        MISS_CONN_CLOSED_INVALID,
        MISS_CONN_RESET,
        MISS_CONN_RESET,
        MISS_CONN_CLOSED_INVALID,
        MISS_CONN_RESET,
    ]
    elapsed = timeit.timeit(
        lambda: [pipeline(l) for l in lines], number=n // 10
    )
    ns_per_line = (elapsed / (n // 10) / len(lines)) * 1e9
    print(f"\n  {'pipeline_mixed_10_lines':30s} {ns_per_line:8.0f} ns/line")

    print()


if __name__ == "__main__":
    main()
