#!/bin/bash
# fail2ban-rs installer
#
# Downloads a prebuilt binary from GitHub Releases and installs it as a
# systemd service. Must be run as root.
#
# Install:
#   curl -sSfL https://raw.githubusercontent.com/aejimmi/fail2ban-rs/main/scripts/install.sh | bash
#
# Install specific version:
#   curl -sSfL https://raw.githubusercontent.com/aejimmi/fail2ban-rs/main/scripts/install.sh | FAIL2BAN_VERSION=0.1.0 bash
#
# Uninstall:
#   curl -sSfL https://raw.githubusercontent.com/aejimmi/fail2ban-rs/main/scripts/install.sh | bash -s -- --uninstall
#
# Environment:
#   FAIL2BAN_VERSION   — version to install (default: latest release)

set -euo pipefail

REPO="aejimmi/fail2ban-rs"
BINARY_NAME="fail2ban-rs"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/fail2ban-rs"
SERVICE_NAME="fail2ban-rs"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

error() { echo -e "${RED}error:${NC} $1" >&2; exit 1; }
warn()  { echo -e "${YELLOW}warning:${NC} $1"; }
info()  { echo -e "${GREEN}::${NC} $1"; }
bold()  { echo -e "${BOLD}$1${NC}"; }

cleanup() {
    [ -n "${TMPDIR:-}" ] && rm -rf "$TMPDIR"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        error "This installer must be run as root. Use: sudo bash install.sh"
    fi
}

check_linux() {
    case "$(uname -s)" in
        Linux) ;;
        *) error "fail2ban-rs only supports Linux (got: $(uname -s))" ;;
    esac
}

check_deps() {
    if ! command -v curl &>/dev/null && ! command -v wget &>/dev/null; then
        error "curl or wget is required"
    fi
    if ! command -v tar &>/dev/null; then
        error "tar is required"
    fi
    if ! command -v systemctl &>/dev/null; then
        error "systemd is required (systemctl not found)"
    fi
}

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)   echo "amd64" ;;
        aarch64|arm64)  echo "arm64" ;;
        *) error "Unsupported architecture: $(uname -m). Supported: x86_64, aarch64" ;;
    esac
}

check_firewall() {
    if command -v nft &>/dev/null; then
        info "Detected firewall backend: nftables"
    elif command -v iptables &>/dev/null; then
        warn "nftables not found — you may need to set backend = \"iptables\" in config"
    else
        warn "Neither nft nor iptables found — firewall commands will fail"
    fi
}

# ---------------------------------------------------------------------------
# Version detection
# ---------------------------------------------------------------------------

get_version() {
    if [ -n "${FAIL2BAN_VERSION:-}" ]; then
        echo "$FAIL2BAN_VERSION"
        return
    fi

    local version
    if command -v curl &>/dev/null; then
        version=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
            | grep '"tag_name"' | head -1 | sed 's/.*"v\([^"]*\)".*/\1/')
    else
        version=$(wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" \
            | grep '"tag_name"' | head -1 | sed 's/.*"v\([^"]*\)".*/\1/')
    fi

    if [ -z "$version" ]; then
        error "Failed to determine latest version. Set FAIL2BAN_VERSION=x.y.z and retry."
    fi
    echo "$version"
}

# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------

download() {
    local url="$1" dest="$2"
    if command -v curl &>/dev/null; then
        curl -fSL --progress-bar -o "$dest" "$url"
    else
        wget --show-progress -qO "$dest" "$url"
    fi
}

# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------

do_uninstall() {
    check_root
    bold "Uninstalling fail2ban-rs..."

    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        info "Stopping service..."
        systemctl stop "$SERVICE_NAME"
    fi
    if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
        systemctl disable "$SERVICE_NAME"
    fi

    [ -f "$SERVICE_FILE" ] && rm -f "$SERVICE_FILE" && info "Removed $SERVICE_FILE"
    [ -f "${INSTALL_DIR}/${BINARY_NAME}" ] && rm -f "${INSTALL_DIR}/${BINARY_NAME}" && info "Removed ${INSTALL_DIR}/${BINARY_NAME}"

    systemctl daemon-reload 2>/dev/null || true

    echo ""
    info "Binary and service removed."
    info "Config and state preserved (remove manually if desired):"
    echo "  rm -rf $CONFIG_DIR"
    echo "  rm -rf /var/lib/fail2ban-rs"
}

# ---------------------------------------------------------------------------
# Install / Upgrade
# ---------------------------------------------------------------------------

do_install() {
    check_root
    check_linux
    check_deps

    local arch
    arch=$(detect_arch)

    echo ""
    bold "fail2ban-rs installer"
    echo ""

    local version
    version=$(get_version)
    info "Version: $version"
    info "Arch:    linux-$arch"
    echo ""

    # Download
    local artifact="fail2ban-rs-${version}-linux-${arch}.tar.gz"
    local url="https://github.com/${REPO}/releases/download/v${version}/${artifact}"
    local checksum_url="${url}.sha256"

    TMPDIR=$(mktemp -d)

    info "Downloading from GitHub Releases..."
    download "$url" "${TMPDIR}/${artifact}" || error "Download failed. Check the version exists: v${version}"

    # Verify checksum
    if download "$checksum_url" "${TMPDIR}/${artifact}.sha256" 2>/dev/null; then
        info "Verifying checksum..."
        (cd "$TMPDIR" && sha256sum -c "${artifact}.sha256" --quiet) || error "Checksum verification failed"
    else
        warn "Checksum not available, skipping verification"
    fi

    # Extract
    tar -xzf "${TMPDIR}/${artifact}" -C "$TMPDIR"
    local extracted="${TMPDIR}/fail2ban-rs-${version}-linux-${arch}"

    if [ ! -f "${extracted}/fail2ban-rs" ]; then
        error "Binary not found in archive"
    fi

    # Detect upgrade vs fresh install
    local upgrade=false
    local was_running=false
    if [ -f "${INSTALL_DIR}/${BINARY_NAME}" ]; then
        upgrade=true
        if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
            was_running=true
            info "Stopping running service..."
            systemctl stop "$SERVICE_NAME"
        fi
    fi

    # Install binary
    install -m 755 "${extracted}/fail2ban-rs" "${INSTALL_DIR}/${BINARY_NAME}"
    info "Installed ${INSTALL_DIR}/${BINARY_NAME}"

    # Install service file (always update — safe, no user data)
    install -m 644 "${extracted}/fail2ban-rs.service" "$SERVICE_FILE"
    systemctl daemon-reload
    info "Installed systemd service"

    # Install config (only on fresh install — never overwrite user config)
    if [ ! -f "${CONFIG_DIR}/config.toml" ]; then
        mkdir -p "${CONFIG_DIR}/config.d"
        install -m 644 "${extracted}/config.toml" "${CONFIG_DIR}/config.toml"
        info "Installed default config to ${CONFIG_DIR}/config.toml"
    else
        info "Config exists, not overwriting: ${CONFIG_DIR}/config.toml"
    fi

    # Check firewall availability
    check_firewall

    # Print status
    echo ""
    bold "---"
    echo ""

    if [ "$upgrade" = true ]; then
        if [ "$was_running" = true ]; then
            systemctl start "$SERVICE_NAME"
            info "Service restarted."
        else
            info "Upgrade complete. Start with: systemctl start $SERVICE_NAME"
        fi
    else
        systemctl enable "$SERVICE_NAME"
        echo "  Installed to:  ${INSTALL_DIR}/${BINARY_NAME}"
        echo "  Config:        ${CONFIG_DIR}/config.toml"
        echo "  Service:       $SERVICE_FILE"
        echo ""
        bold "Next steps:"
        echo "  1. Edit config:     nano ${CONFIG_DIR}/config.toml"
        echo "  2. Start service:   systemctl start $SERVICE_NAME"
        echo "  3. Check status:    $BINARY_NAME status"
        echo "  4. View logs:       journalctl -u $SERVICE_NAME -f"
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

case "${1:-}" in
    --uninstall|-u)
        do_uninstall
        ;;
    --help|-h)
        echo "Usage: sudo bash install.sh [--uninstall]"
        echo ""
        echo "Environment:"
        echo "  FAIL2BAN_VERSION=x.y.z    Install a specific version (default: latest)"
        ;;
    *)
        do_install
        ;;
esac
