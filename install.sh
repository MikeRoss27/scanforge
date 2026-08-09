#!/usr/bin/env bash
# ScanForge - install script (Linux / macOS / Git-Bash on Windows)
#
# Quick install (prebuilt binary from GitHub Releases, no Go required):
#   curl -fsSL https://raw.githubusercontent.com/MikeRoss27/scanforge/main/install.sh | bash
#
# Full install (binary + all external tools, requires Go):
#   curl -fsSL https://raw.githubusercontent.com/MikeRoss27/scanforge/main/install.sh | bash -s -- --full
#
# Options:
#   --full                  Also install external tools (nmap, nuclei, subfinder, ...)
#   --version <vX.Y.Z>      Version to install (default: latest)
#   --dir <path>            Install directory (default: ~/.local/bin)
#   -h, --help              Show help
#
# Environment variables: SCANFORGE_VERSION, SCANFORGE_INSTALL_DIR

set -euo pipefail

REPO="MikeRoss27/scanforge"
RAW_BASE="https://raw.githubusercontent.com/${REPO}/main"
API_BASE="https://api.github.com/repos/${REPO}"

VERSION="latest"
INSTALL_DIR=""
MODE="binary"

usage() {
    sed -n '2,20p' "${BASH_SOURCE[0]}"
    exit 0
}

while [ $# -gt 0 ]; do
    case "$1" in
        --full) MODE="full" ;;
        --version) VERSION="$2"; shift ;;
        --version=*) VERSION="${1#*=}" ;;
        --dir) INSTALL_DIR="$2"; shift ;;
        --dir=*) INSTALL_DIR="${1#*=}" ;;
        -h|--help) usage ;;
        *) echo "Unknown option: $1" >&2; usage ;;
    esac
    shift
done

info() { printf "\033[36m%s\033[0m\n" "$*"; }
ok()   { printf "\033[32m[OK] %s\033[0m\n" "$*"; }
warn() { printf "\033[33m[WARNING] %s\033[0m\n" "$*"; }
err()  { printf "\033[31m[ERROR] %s\033[0m\n" "$*" >&2; exit 1; }

detect_os() {
    case "$(uname -s)" in
        Linux*)  OS="linux" ;;
        Darwin*) OS="darwin" ;;
        MINGW*|MSYS*|CYGWIN*) OS="windows" ;;
        *) err "Unsupported operating system: $(uname -s)" ;;
    esac
}

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)        ARCH="amd64" ;;
        aarch64|arm64)       ARCH="arm64" ;;
        i386|i686)           warn "No 386 builds published, falling back to amd64" ; ARCH="amd64" ;;
        *)                   warn "Unsupported architecture $(uname -m), trying amd64" ; ARCH="amd64" ;;
    esac
}

resolve_version() {
    if [ "$VERSION" = "latest" ]; then
        info "Fetching the latest available version..."
        TAG="$(curl -fsSL "${API_BASE}/releases/latest" 2>/dev/null \
            | grep -o '"tag_name": *"[^"]*"' \
            | head -1 \
            | sed -E 's/.*"([^"]*)"$/\1/')" || true
        [ -n "$TAG" ] || err "Unable to determine the latest version"
        VERSION="${TAG#v}"
    else
        VERSION="${VERSION#v}"
    fi
    info "Target version: ${VERSION}"
}

file_sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | cut -d' ' -f1
    else
        return 1
    fi
}

install_scanforge() {
    command -v curl >/dev/null 2>&1 || err "curl is required for installation"

    detect_os
    detect_arch
    resolve_version

    ARCHIVE_EXT="tar.gz"
    BIN_NAME="scanforge"
    if [ "$OS" = "windows" ]; then
        ARCHIVE_EXT="zip"
        BIN_NAME="scanforge.exe"
    fi

    ASSET="scanforge_${VERSION}_${OS}_${ARCH}.${ARCHIVE_EXT}"
    URL="https://github.com/${REPO}/releases/download/v${VERSION}/${ASSET}"

    DEST="${INSTALL_DIR:-${SCANFORGE_INSTALL_DIR:-}}"
    if [ -z "$DEST" ]; then
        DEST="${HOME}/.local/bin"
    fi
    mkdir -p "$DEST"

    TMPDIR="$(mktemp -d)"
    trap 'rm -rf "$TMPDIR"' EXIT

    info "Downloading ${ASSET} ..."
    if ! curl -fsSL "$URL" -o "${TMPDIR}/${ASSET}"; then
        err "Asset not found for version v${VERSION}. See https://github.com/${REPO}/releases"
    fi

    # Extract the archive
    case "$ARCHIVE_EXT" in
        tar.gz)
            tar -xzf "${TMPDIR}/${ASSET}" -C "$TMPDIR" ;;
        zip)
            if command -v unzip >/dev/null 2>&1; then
                unzip -qo "${TMPDIR}/${ASSET}" -d "$TMPDIR"
            elif command -v python3 >/dev/null 2>&1; then
                python3 -m zipfile -e "${TMPDIR}/${ASSET}" "$TMPDIR"
            else
                err "No zip extraction tool available (unzip or python3 required)"
            fi
            ;;
    esac

    # Locate the binary inside the archive
    BIN=""
    for CAND in "${TMPDIR}"/scanforge*; do
        [ -f "$CAND" ] || continue
        BASE="$(basename "$CAND")"
        case "$BASE" in
            *.sha256|*.txt|*.md|*.zip|*.gz) continue ;;
        esac
        if [ -z "$BIN" ] || [ "$BASE" = "$BIN_NAME" ]; then
            BIN="$CAND"
        fi
    done
    [ -n "$BIN" ] || err "Binary not found in the archive"

    # Verify the SHA-256 checksum
    SUM_FILE="$(find "$TMPDIR" -maxdepth 1 -name '*.sha256' | head -1)"
    EXPECTED=""
    if [ -n "$SUM_FILE" ]; then
        EXPECTED="$(cut -d' ' -f1 "$SUM_FILE")"
        ACTUAL="$(file_sha256 "$BIN" || true)"
    elif curl -fsSL "https://github.com/${REPO}/releases/download/v${VERSION}/checksums.txt" -o "${TMPDIR}/checksums.txt" 2>/dev/null; then
        EXPECTED="$(awk -v n="${ASSET}" '$2 == n {print $1}' "${TMPDIR}/checksums.txt")"
        ACTUAL="$(file_sha256 "${TMPDIR}/${ASSET}" || true)"
    fi
    if [ -n "$EXPECTED" ] && [ -n "$ACTUAL" ] && [ "$EXPECTED" = "$ACTUAL" ]; then
        ok "SHA-256 checksum verified"
    else
        warn "Unable to verify the SHA-256 checksum"
    fi

    chmod +x "$BIN"
    mv -f "$BIN" "${DEST}/${BIN_NAME}"
    ok "ScanForge ${VERSION} installed in ${DEST}/${BIN_NAME}"
}

install_full() {
    # .tools-version: local when the repo is cloned, otherwise fetched from GitHub
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || echo /tmp)"
    if [ -f "${SCRIPT_DIR}/.tools-version" ]; then
        TOOLS_FILE="${SCRIPT_DIR}/.tools-version"
    else
        info "Fetching pinned tool versions (.tools-version)..."
        TOOLS_FILE="/tmp/scanforge-tools-version"
        curl -fsSL "${RAW_BASE}/.tools-version" -o "$TOOLS_FILE" \
            || err "Unable to fetch .tools-version"
    fi
    # shellcheck source=/dev/null
    source "$TOOLS_FILE"

    command -v go >/dev/null 2>&1 || err "Go is not installed or missing from PATH (https://go.dev/dl/)"
    ok "Go is installed: $(go version)"

    # System packages (non-Go tools)
    if command -v apt >/dev/null 2>&1; then
        info "Installing system packages (nmap, python3, whatweb, wafw00f)..."
        sudo apt update
        sudo apt install -y nmap python3 python3-pip whatweb wafw00f massdns
    elif command -v brew >/dev/null 2>&1; then
        info "Installing system packages via Homebrew (nmap, whatweb, python3)..."
        brew install nmap whatweb python3 massdns
        pip3 install --user wafw00f || true
    else
        warn "Neither apt nor brew found. Install manually: nmap, python3, whatweb, wafw00f (pip install wafw00f)"
    fi

    TOOLS=(
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@${SUBFINDER_VERSION}"
        "github.com/projectdiscovery/dnsx/cmd/dnsx@${DNSX_VERSION}"
        "github.com/projectdiscovery/httpx/cmd/httpx@${HTTPX_VERSION}"
        "github.com/projectdiscovery/naabu/v2/cmd/naabu@${NAABU_VERSION}"
        "github.com/projectdiscovery/katana/cmd/katana@${KATANA_VERSION}"
        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION}"
        "github.com/projectdiscovery/tlsx/cmd/tlsx@${TLSX_VERSION}"
        "github.com/lc/gau/v2/cmd/gau@${GAU_VERSION}"
        "github.com/ffuf/ffuf/v2@${FFUF_VERSION}"
        "github.com/projectdiscovery/shuffledns/cmd/shuffledns@${SHUFFLEDNS_VERSION}"
    )

    info "Installing Go tools (pinned versions)... This may take a few minutes."
    for TOOL in "${TOOLS[@]}"; do
        echo "-> Installing ${TOOL} ..."
        go install "$TOOL"
        ok "Installed"
    done

    info "Installing the ScanForge binary..."
    install_scanforge
}

case "$MODE" in
    binary) install_scanforge ;;
    full)   install_full ;;
esac

echo ""
info "Installation complete!"
if ! command -v scanforge >/dev/null 2>&1; then
    warn "Add the install directory to your PATH:"
    echo "    export PATH=\"${DEST}:${PATH}\""
fi
echo "    scanforge init"
echo "    scanforge doctor"
