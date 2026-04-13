#!/bin/bash
# Build release artifacts for Linux targets.
# Usage: ./scripts/build-release.sh 0.1.0
#
# Prerequisites:
#   brew install zig             (macOS cross-compilation)
#   cargo install cargo-zigbuild
#   rustup target add x86_64-unknown-linux-musl
#   rustup target add aarch64-unknown-linux-musl

set -e

VERSION="${1:-}"

if [ -z "$VERSION" ]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 0.1.0"
    exit 1
fi

if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Error: Version must be in format X.Y.Z"
    exit 1
fi

# Check Cargo.toml version matches
CARGO_VERSION=$(grep -m1 '^version = ' Cargo.toml | sed 's/version = "\(.*\)"/\1/')
if [ "$CARGO_VERSION" != "$VERSION" ]; then
    echo "Error: Version $VERSION does not match Cargo.toml version $CARGO_VERSION"
    exit 1
fi

echo "Building fail2ban-rs v$VERSION"
echo "================================"

DIST_DIR="dist/v$VERSION"
rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

TARGETS=(
    "x86_64-unknown-linux-musl:linux-amd64"
    "aarch64-unknown-linux-musl:linux-arm64"
)

for target_pair in "${TARGETS[@]}"; do
    RUST_TARGET="${target_pair%%:*}"
    LABEL="${target_pair##*:}"

    echo ""
    echo "Building for $LABEL ($RUST_TARGET)..."

    cargo zigbuild --release --target "$RUST_TARGET"

    BINARY="target/$RUST_TARGET/release/fail2ban-rs"

    if [ ! -f "$BINARY" ]; then
        echo "Error: Binary not found at $BINARY"
        exit 1
    fi

    # Strip binary
    if command -v llvm-strip &> /dev/null; then
        llvm-strip "$BINARY"
    elif command -v strip &> /dev/null; then
        strip "$BINARY" 2>/dev/null || true
    fi

    # Package
    ARCHIVE_NAME="fail2ban-rs-${VERSION}-${LABEL}"
    ARCHIVE_DIR="$DIST_DIR/$ARCHIVE_NAME"

    mkdir -p "$ARCHIVE_DIR"
    cp "$BINARY" "$ARCHIVE_DIR/fail2ban-rs"
    cp dist/fail2ban-rs.service "$ARCHIVE_DIR/"
    cp config/default.toml "$ARCHIVE_DIR/config.toml"
    cp LICENSE "$ARCHIVE_DIR/" 2>/dev/null || true
    cp README.md "$ARCHIVE_DIR/" 2>/dev/null || true

    (cd "$DIST_DIR" && tar -czf "$ARCHIVE_NAME.tar.gz" "$ARCHIVE_NAME")
    rm -rf "$ARCHIVE_DIR"

    # Checksum
    (cd "$DIST_DIR" && shasum -a 256 "$ARCHIVE_NAME.tar.gz" > "$ARCHIVE_NAME.tar.gz.sha256")

    echo "Created: $ARCHIVE_NAME.tar.gz"
done

echo ""
echo "================================"
echo "Build complete! Artifacts in $DIST_DIR:"
echo ""
ls -la "$DIST_DIR"

echo ""
echo "To release:"
echo "  git tag v$VERSION && git push origin main --tags"
