#!/usr/bin/env bash
# ScanForge installer for Linux and macOS (Git Bash supports binary-only mode).
# Usage: ./install.sh [--full] [--version vX.Y.Z] [--dir PATH]

set -euo pipefail

REPO="MikeRoss27/scanforge"
RAW_BASE="https://raw.githubusercontent.com/${REPO}/main"
API_BASE="https://api.github.com/repos/${REPO}"
VERSION="${SCANFORGE_VERSION:-latest}"
INSTALL_DIR="${SCANFORGE_INSTALL_DIR:-}"
MODE="binary"
OS=""
ARCH=""
PACKAGE_MANAGER=""
DEST=""
TEMP_ROOT=""
TOOLS_FILE=""

info() { printf '\033[36m%s\033[0m\n' "$*"; }
ok() { printf '\033[32m[OK] %s\033[0m\n' "$*"; }
warn() { printf '\033[33m[WARNING] %s\033[0m\n' "$*" >&2; }
err() { printf '\033[31m[ERROR] %s\033[0m\n' "$*" >&2; exit 1; }

usage() { sed -n '2,3p' "${BASH_SOURCE[0]}"; }

parse_args() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --full) MODE="full" ;;
            --version)
                [ "$#" -ge 2 ] || err "--version requires a value"
                VERSION="$2"; shift
                ;;
            --version=*) VERSION="${1#*=}" ;;
            --dir)
                [ "$#" -ge 2 ] || err "--dir requires a value"
                INSTALL_DIR="$2"; shift
                ;;
            --dir=*) INSTALL_DIR="${1#*=}" ;;
            -h|--help) usage; exit 0 ;;
            *) usage >&2; err "Unknown option: $1" ;;
        esac
        shift
    done
}

cleanup() {
    if [ -n "$TEMP_ROOT" ] && [ -d "$TEMP_ROOT" ]; then
        rm -rf -- "$TEMP_ROOT"
    fi
}
trap cleanup EXIT HUP INT TERM

make_temp_dir() {
    [ -n "$TEMP_ROOT" ] && return
    TEMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/scanforge.XXXXXXXX")" \
        || err "Unable to create a secure temporary directory"
}

detect_os() {
    local kernel="${1:-${SCANFORGE_UNAME_S:-$(uname -s)}}"
    case "$kernel" in
        Linux*) OS="linux" ;;
        Darwin*) OS="darwin" ;;
        MINGW*|MSYS*|CYGWIN*) OS="windows" ;;
        *) err "Unsupported operating system: ${kernel}" ;;
    esac
}

detect_arch() {
    local machine="${1:-${SCANFORGE_UNAME_M:-$(uname -m)}}"
    case "$machine" in
        x86_64|amd64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        i386|i486|i586|i686|x86)
            err "Unsupported 32-bit architecture: ${machine}; ScanForge publishes no 386 build"
            ;;
        *) err "Unsupported architecture: ${machine}; no compatible ScanForge build is published" ;;
    esac
    if [ "$OS" = "windows" ] && [ "$ARCH" != "amd64" ]; then
        err "Unsupported Windows architecture: ${machine}; only windows/amd64 is published"
    fi
}

detect_package_manager() {
    PACKAGE_MANAGER="none"
    if [ "$OS" = "linux" ] && command -v pacman >/dev/null 2>&1; then
        PACKAGE_MANAGER="pacman"
    elif [ "$OS" = "linux" ] && command -v apt-get >/dev/null 2>&1; then
        PACKAGE_MANAGER="apt"
    elif [ "$OS" = "darwin" ] && command -v brew >/dev/null 2>&1; then
        PACKAGE_MANAGER="brew"
    fi
}

resolve_version() {
    command -v curl >/dev/null 2>&1 || err "curl is required for installation"
    if [ "$VERSION" = "latest" ]; then
        local release_json tag
        info "Fetching the latest available version..."
        release_json="$(curl -fsSL "${API_BASE}/releases/latest")" \
            || err "Unable to query the latest GitHub release"
        tag="$(printf '%s' "$release_json" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)"
        [ -n "$tag" ] || err "Unable to determine the latest release version"
        VERSION="${tag#v}"
    else
        VERSION="${VERSION#v}"
    fi
    case "$VERSION" in ''|*[!0-9A-Za-z._+-]*) err "Invalid version: ${VERSION}" ;; esac
    info "Target version: ${VERSION}"
}

file_sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print tolower($1)}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print tolower($1)}'
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 "$1" | awk '{print tolower($NF)}'
    else
        return 1
    fi
}

checksum_entry() {
    local checksum_file="$1" artifact_name="$2"
    awk -v name="$artifact_name" '{ file=$2; sub(/^\*/, "", file); if (file == name) { print tolower($1); found=1; exit } } END { if (!found) exit 1 }' "$checksum_file"
}

verify_checksum() {
    local file="$1" expected="$2" label="$3" actual normalized
    normalized="$(printf '%s' "$expected" | tr '[:upper:]' '[:lower:]')"
    case "$normalized" in *[!0-9a-f]*) err "Invalid SHA-256 value for ${label}" ;; esac
    [ "${#normalized}" -eq 64 ] || err "Invalid SHA-256 length for ${label}"
    actual="$(file_sha256 "$file")" \
        || err "Cannot verify ${label}: install sha256sum, shasum, or openssl"
    [ "$actual" = "$normalized" ] \
        || err "SHA-256 mismatch for ${label}: expected ${normalized}, got ${actual}"
    ok "SHA-256 verified (${label})"
}

validate_archive_members() {
    local archive="$1" extension="$2" entry list_file
    make_temp_dir
    list_file="${TEMP_ROOT}/archive-members.txt"
    case "$extension" in
        tar.gz) tar -tzf "$archive" > "$list_file" || err "Invalid tar archive" ;;
        zip)
            if command -v unzip >/dev/null 2>&1; then
                unzip -Z1 "$archive" > "$list_file" || err "Invalid zip archive"
            elif command -v python3 >/dev/null 2>&1; then
                python3 -m zipfile -l "$archive" | awk 'NR > 2 && NF {print $NF}' > "$list_file"
            else
                err "unzip or python3 is required to inspect zip archives"
            fi
            ;;
    esac
    while IFS= read -r entry; do
        case "$entry" in /*|../*|*/../*|*/..) err "Unsafe path in release archive: ${entry}" ;; esac
    done < "$list_file"
}

extract_archive() {
    local archive="$1" extension="$2" destination="$3"
    validate_archive_members "$archive" "$extension"
    case "$extension" in
        tar.gz) tar -xzf "$archive" -C "$destination" ;;
        zip)
            if command -v unzip >/dev/null 2>&1; then
                unzip -qo "$archive" -d "$destination"
            else
                python3 -m zipfile -e "$archive" "$destination"
            fi
            ;;
    esac
}

install_scanforge() {
    local extension="tar.gz" binary_name="scanforge" release_name asset url archive
    local checksums expected binary embedded_checksum embedded_expected checksum_url http_code
    detect_os
    detect_arch
    resolve_version
    make_temp_dir
    if [ "$OS" = "windows" ]; then extension="zip"; binary_name="scanforge.exe"; fi
    release_name="scanforge_${VERSION}_${OS}_${ARCH}"
    asset="${release_name}.${extension}"
    url="https://github.com/${REPO}/releases/download/v${VERSION}/${asset}"
    archive="${TEMP_ROOT}/${asset}"
    checksums="${TEMP_ROOT}/checksums.txt"
    DEST="${INSTALL_DIR:-${HOME}/.local/bin}"
    mkdir -p -- "$DEST"

    info "Downloading ${asset} ..."
    curl -fsSL "$url" -o "$archive" || err "Release asset not found: ${url}"
    checksum_url="https://github.com/${REPO}/releases/download/v${VERSION}/checksums.txt"
    http_code="$(curl -sSL -w '%{http_code}' "$checksum_url" -o "$checksums")" \
        || err "Unable to download release checksums from ${checksum_url}"
    case "$http_code" in
        200)
            expected="$(checksum_entry "$checksums" "$asset")" \
                || err "checksums.txt exists but has no entry for ${asset}"
            verify_checksum "$archive" "$expected" "release archive ${asset}"
            ;;
        404) warn "Release v${VERSION} has no checksums.txt; integrity verification is unavailable for this legacy release" ;;
        *) err "Unable to download release checksums: HTTP ${http_code}" ;;
    esac

    extract_archive "$archive" "$extension" "$TEMP_ROOT"
    binary="${TEMP_ROOT}/${release_name}"
    [ "$OS" = "windows" ] && binary="${binary}.exe"
    [ -f "$binary" ] || err "Expected binary not found in archive: $(basename "$binary")"
    embedded_checksum="${TEMP_ROOT}/${release_name}.sha256"
    if [ -f "$embedded_checksum" ]; then
        embedded_expected="$(checksum_entry "$embedded_checksum" "$(basename "$binary")")" \
            || err "Embedded checksum does not name $(basename "$binary")"
        verify_checksum "$binary" "$embedded_expected" "extracted binary $(basename "$binary")"
    else
        warn "Archive contains no binary checksum; archive checksum was the only integrity check"
    fi
    chmod +x "$binary"
    mv -f -- "$binary" "${DEST}/${binary_name}"
    ok "ScanForge ${VERSION} installed in ${DEST}/${binary_name}"
}

load_tool_versions() {
    local script_dir line key value
    make_temp_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || true)"
    if [ -n "$script_dir" ] && [ -f "${script_dir}/.tools-version" ]; then
        TOOLS_FILE="${script_dir}/.tools-version"
    else
        TOOLS_FILE="${TEMP_ROOT}/tools-version"
        info "Fetching pinned tool versions (.tools-version)..."
        curl -fsSL "${RAW_BASE}/.tools-version" -o "$TOOLS_FILE" || err "Unable to fetch .tools-version"
    fi
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in ''|'#'*) continue ;; esac
        case "$line" in [A-Z_]*=*) ;; *) err "Invalid entry in .tools-version: ${line}" ;; esac
        key="${line%%=*}"; value="${line#*=}"
        case "$key" in
            SUBFINDER_VERSION|DNSX_VERSION|HTTPX_VERSION|NAABU_VERSION|KATANA_VERSION|NUCLEI_VERSION|TLSX_VERSION|GAU_VERSION|FFUF_VERSION|SHUFFLEDNS_VERSION|SECLISTS_VERSION|SECLISTS_DNS_SHA256|MASSDNS_VERSION|MASSDNS_SOURCE_SHA256|WAFW00F_VERSION) ;;
            *) err "Unknown key in .tools-version: ${key}" ;;
        esac
        printf -v "$key" '%s' "$value"
    done < "$TOOLS_FILE"
    for key in SUBFINDER_VERSION DNSX_VERSION HTTPX_VERSION NAABU_VERSION KATANA_VERSION NUCLEI_VERSION TLSX_VERSION GAU_VERSION FFUF_VERSION SHUFFLEDNS_VERSION SECLISTS_VERSION SECLISTS_DNS_SHA256 MASSDNS_VERSION MASSDNS_SOURCE_SHA256 WAFW00F_VERSION; do
        [ -n "${!key:-}" ] || err "Missing ${key} in .tools-version"
    done
}

root_command() {
    if [ "$(id -u)" -eq 0 ]; then "$@"
    elif command -v sudo >/dev/null 2>&1; then sudo "$@"
    else err "Root privileges are required for system packages, but sudo is unavailable"
    fi
}

packages_for_manager() {
    case "$1" in
        pacman) printf '%s\n' nmap chromium go python-pipx base-devel ;;
        apt) printf '%s\n' nmap python3 python3-venv pipx whatweb chromium build-essential ;;
        brew) printf '%s\n' nmap massdns go pipx ;;
    esac
}

install_system_packages() {
    local candidate
    local -a packages=() available=()
    detect_package_manager
    while IFS= read -r candidate; do [ -n "$candidate" ] && packages+=("$candidate"); done < <(packages_for_manager "$PACKAGE_MANAGER")
    case "$PACKAGE_MANAGER" in
        pacman)
            info "Installing official Arch packages with pacman (no system upgrade)..."
            root_command pacman -S --needed --noconfirm "${packages[@]}"
            ;;
        apt)
            info "Refreshing apt metadata and installing available system dependencies..."
            root_command apt-get update
            for candidate in "${packages[@]}"; do
                if apt-cache show "$candidate" >/dev/null 2>&1; then available+=("$candidate")
                else warn "apt package unavailable on this release: ${candidate}"
                fi
            done
            [ "${#available[@]}" -eq 0 ] || root_command apt-get install -y --no-install-recommends "${available[@]}"
            ;;
        brew) info "Installing Homebrew formulae..."; brew install "${packages[@]}" ;;
        none) warn "No supported package manager found; system dependencies must be installed manually" ;;
    esac
}

install_go_tools() {
    local tool
    local -a tools=(
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
    command -v go >/dev/null 2>&1 || err "Go is required for --full; see https://go.dev/dl/"
    ok "Go is installed: $(go version)"
    info "Installing Go tools at pinned versions..."
    for tool in "${tools[@]}"; do info "Installing ${tool}"; go install "$tool"; done
}

install_python_tools() {
    if command -v pipx >/dev/null 2>&1; then
        info "Installing wafw00f in an isolated pipx environment..."
        pipx install --force "wafw00f==${WAFW00F_VERSION#v}"
    elif command -v wafw00f >/dev/null 2>&1; then
        warn "wafw00f exists but pipx is unavailable, so its pinned version could not be enforced"
    else warn "pipx is unavailable; install wafw00f manually with pipx (global pip is intentionally not used)"
    fi
}

install_dns_wordlist() {
    local data_home target downloaded url
    data_home="${XDG_DATA_HOME:-${HOME}/.local/share}"
    target="${data_home}/scanforge/wordlists/subdomains-top1million-5000.txt"
    downloaded="${TEMP_ROOT}/subdomains-top1million-5000.txt"
    url="https://raw.githubusercontent.com/danielmiessler/SecLists/${SECLISTS_VERSION}/Discovery/DNS/subdomains-top1million-5000.txt"
    info "Downloading the pinned SecLists DNS wordlist..."
    curl -fsSL "$url" -o "$downloaded" || err "Unable to download the SecLists DNS wordlist"
    verify_checksum "$downloaded" "$SECLISTS_DNS_SHA256" "SecLists DNS wordlist ${SECLISTS_VERSION}"
    mkdir -p -- "$(dirname "$target")"
    cp -- "$downloaded" "$target"
    ok "DNS wordlist installed in ${target}"
}

install_massdns() {
    local archive source_dir version
    command -v massdns >/dev/null 2>&1 && { ok "massdns is already installed"; return; }
    command -v make >/dev/null 2>&1 || { warn "make is unavailable; massdns remains manual"; return; }
    command -v cc >/dev/null 2>&1 || { warn "a C compiler is unavailable; massdns remains manual"; return; }
    version="${MASSDNS_VERSION#v}"
    archive="${TEMP_ROOT}/massdns-${version}.tar.gz"
    info "Downloading massdns ${MASSDNS_VERSION} source..."
    curl -fsSL "https://github.com/blechschmidt/massdns/archive/refs/tags/${MASSDNS_VERSION}.tar.gz" -o "$archive" \
        || err "Unable to download massdns source"
    verify_checksum "$archive" "$MASSDNS_SOURCE_SHA256" "massdns source archive ${MASSDNS_VERSION}"
    validate_archive_members "$archive" tar.gz
    tar -xzf "$archive" -C "$TEMP_ROOT"
    source_dir="${TEMP_ROOT}/massdns-${version}"
    make -C "$source_dir"
    mkdir -p -- "${HOME}/.local/bin"
    cp -- "${source_dir}/bin/massdns" "${HOME}/.local/bin/massdns"
    chmod +x "${HOME}/.local/bin/massdns"
    ok "massdns installed in ${HOME}/.local/bin/massdns"
}

has_browser() {
    command -v chromium >/dev/null 2>&1 || command -v chromium-browser >/dev/null 2>&1 ||
        command -v google-chrome >/dev/null 2>&1 || command -v google-chrome-stable >/dev/null 2>&1 ||
        [ -x "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" ] ||
        [ -x "/Applications/Chromium.app/Contents/MacOS/Chromium" ]
}

verify_full_install() {
    local tool missing=0
    local -a required=(subfinder shuffledns dnsx httpx naabu nmap whatweb wafw00f katana ffuf nuclei gau tlsx massdns)
    info "Verifying external dependencies..."
    for tool in "${required[@]}"; do
        if command -v "$tool" >/dev/null 2>&1; then ok "${tool}: installed"
        else warn "${tool}: missing"; missing=1
        fi
    done
    if has_browser; then ok "chromium/chrome: installed"
    else warn "chromium/chrome: missing (optional, used by jsverify)"
    fi
    case "$PACKAGE_MANAGER" in
        pacman) warn "Arch manual/AUR-only item: whatweb (massdns and the DNS wordlist were installed from verified upstream artifacts)" ;;
        brew) warn "macOS manual item: whatweb; install a Chrome-family browser for jsverify if desired" ;;
        none) warn "Install missing tools using platform packages, upstream releases, or Docker" ;;
    esac
    [ "$missing" -eq 0 ] || warn "--full completed with manual dependencies; run 'scanforge doctor --profile <name>' for profile-specific guidance"
}

install_full() {
    detect_os
    [ "$OS" != "windows" ] || err "Use install.ps1 -Full on Windows"
    load_tool_versions
    install_system_packages
    install_go_tools
    install_python_tools
    install_dns_wordlist
    install_massdns
    install_scanforge
    verify_full_install
}

main() {
    parse_args "$@"
    case "$MODE" in binary) install_scanforge ;; full) install_full ;; esac
    printf '\n'; info "Installation complete"
    if ! command -v scanforge >/dev/null 2>&1; then
        warn "Add the installation directories to PATH if necessary:"
        # shellcheck disable=SC2016 # $PATH must remain literal for the user's shell.
        printf '    export PATH="%s:%s/bin:$PATH"\n' "$DEST" "$(go env GOPATH 2>/dev/null || printf '%s/go' "$HOME")"
    fi
    printf '    scanforge init\n    scanforge doctor\n'
}

if [ "${SCANFORGE_INSTALLER_TESTING:-0}" != "1" ]; then main "$@"; fi
