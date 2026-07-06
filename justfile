# Project task runner — run `just --list` for available recipes

# Run all tests
test:
    cargo test --no-fail-fast

# Run all tests including optional features (tell)
test-all-features:
    cargo test --all-features --no-fail-fast

# Run clippy lints
lint:
    cargo clippy --all-targets -- -D warnings

# Check formatting
fmt:
    cargo fmt --all -- --check

# Fix formatting
fmt-fix:
    cargo fmt --all

# Run cargo-deny checks (licenses, advisories, bans, sources)
deny:
    cargo deny check

# Run test coverage
coverage:
    cargo llvm-cov --all --ignore-filename-regex '_test\.rs$'

# Run test coverage and open HTML report
coverage-html:
    cargo llvm-cov --all --ignore-filename-regex '_test\.rs$' --html --open

# Run benchmarks
bench:
    cargo bench

# Run all checks (lint, fmt, test, deny)
check-all: lint fmt test deny
