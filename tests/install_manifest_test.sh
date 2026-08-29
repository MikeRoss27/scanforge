#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

fail=0
while IFS='=' read -r key version; do
    case "$key" in ''|'#'*) continue ;; esac
    case "$key" in
        SECLISTS_VERSION) [[ "$version" =~ ^[0-9]+\.[0-9]+$ ]] || fail=1 ;;
        SECLISTS_DNS_SHA256|MASSDNS_SOURCE_SHA256) [[ "$version" =~ ^[0-9a-f]{64}$ ]] || fail=1 ;;
        *_VERSION) [[ "$version" =~ ^v[0-9] ]] || fail=1 ;;
        *) printf 'Unknown .tools-version key: %s\n' "$key" >&2; fail=1 ;;
    esac
    for consumer in install.sh install.ps1 Dockerfile; do
        if ! grep -q "$key" "$consumer"; then
            printf '%s does not consume %s\n' "$consumer" "$key" >&2
            fail=1
        fi
    done
done < .tools-version

if grep -REn '^[[:space:]]*(SUBFINDER_VERSION|DNSX_VERSION|HTTPX_VERSION|NAABU_VERSION|KATANA_VERSION|NUCLEI_VERSION|TLSX_VERSION|GAU_VERSION|FFUF_VERSION|SHUFFLEDNS_VERSION|WAFW00F_VERSION|MASSDNS_VERSION|SECLISTS_VERSION)=' \
    --binary-files=without-match --exclude=.tools-version --exclude=scanforge --exclude-dir=.git .; then
    printf 'Pinned tool versions must only be assigned in .tools-version\n' >&2
    fail=1
fi

exit "$fail"
