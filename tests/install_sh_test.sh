#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export SCANFORGE_INSTALLER_TESTING=1
# shellcheck source=../install.sh
# shellcheck disable=SC1091
source "${REPO_ROOT}/install.sh"

TEST_TEMP="$(mktemp -d "${TMPDIR:-/tmp}/scanforge-install-test.XXXXXXXX")"
trap 'cleanup; rm -rf -- "$TEST_TEMP"' EXIT
TESTS=0

assert_equal() {
    TESTS=$((TESTS + 1))
    if [ "$1" != "$2" ]; then
        printf 'not ok %d - expected %q, got %q\n' "$TESTS" "$2" "$1" >&2
        exit 1
    fi
    printf 'ok %d\n' "$TESTS"
}

detect_os Linux
assert_equal "$OS" linux
detect_os Darwin
assert_equal "$OS" darwin

OS=linux
detect_arch x86_64
assert_equal "$ARCH" amd64
detect_arch aarch64
assert_equal "$ARCH" arm64
if (detect_arch i686) >/dev/null 2>&1; then
    printf 'expected i686 detection to fail\n' >&2
    exit 1
fi
TESTS=$((TESTS + 1)); printf 'ok %d\n' "$TESTS"
if (detect_arch riscv64) >/dev/null 2>&1; then
    printf 'expected unknown architecture detection to fail\n' >&2
    exit 1
fi
TESTS=$((TESTS + 1)); printf 'ok %d\n' "$TESTS"

mkdir "${TEST_TEMP}/bin"
touch "${TEST_TEMP}/bin/pacman"
chmod +x "${TEST_TEMP}/bin/pacman"
old_path="$PATH"
PATH="${TEST_TEMP}/bin"
OS=linux
detect_package_manager
PATH="$old_path"
assert_equal "$PACKAGE_MANAGER" pacman

load_tool_versions
assert_equal "$SUBFINDER_VERSION" v2.15.0
assert_equal "$WAFW00F_VERSION" v2.4.2

arch_packages="$(packages_for_manager pacman)"
assert_equal "$arch_packages" $'nmap\nchromium\ngo\npython-pipx\nbase-devel'
if printf '%s\n' "$arch_packages" | grep -Eq 'whatweb|wafw00f|massdns'; then
    printf 'AUR-only packages must not be passed to pacman\n' >&2
    exit 1
fi
TESTS=$((TESTS + 1)); printf 'ok %d\n' "$TESTS"

mkdir "${TEST_TEMP}/empty-bin"
if (PATH="${TEST_TEMP}/empty-bin" file_sha256 "${TEST_TEMP}/payload") >/dev/null 2>&1; then
    printf 'expected missing SHA-256 implementation to fail\n' >&2
    exit 1
fi
TESTS=$((TESTS + 1)); printf 'ok %d\n' "$TESTS"

printf 'verified payload\n' > "${TEST_TEMP}/payload"
digest="$(file_sha256 "${TEST_TEMP}/payload")"
verify_checksum "${TEST_TEMP}/payload" "$digest" test >/dev/null
TESTS=$((TESTS + 1)); printf 'ok %d\n' "$TESTS"
bad_digest="$(printf '%064d' 0)"
if (verify_checksum "${TEST_TEMP}/payload" "$bad_digest" test) >/dev/null 2>&1; then
    printf 'expected checksum mismatch to fail\n' >&2
    exit 1
fi
TESTS=$((TESTS + 1)); printf 'ok %d\n' "$TESTS"

printf '%s  artifact.tar.gz\n' "$digest" > "${TEST_TEMP}/checksums.txt"
assert_equal "$(checksum_entry "${TEST_TEMP}/checksums.txt" artifact.tar.gz)" "$digest"
if (checksum_entry "${TEST_TEMP}/checksums.txt" missing.tar.gz) >/dev/null 2>&1; then
    printf 'expected missing checksum entry to fail\n' >&2
    exit 1
fi
TESTS=$((TESTS + 1)); printf 'ok %d\n' "$TESTS"

printf '1..%d\n' "$TESTS"
