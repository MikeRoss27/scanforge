<p align="center">
  <img src="public/SCANFORGE.gif" width="100%" alt="ScanForge">
</p>

# ScanForge

**ScanForge** is a command-line tool (CLI) written in Go, designed to securely and structurally orchestrate your penetration testing and reconnaissance (recon) workflows.

Thanks to its artifact-driven architecture, ScanForge chains well-known security tools while enforcing extremely strict scope validation rules to prevent any unauthorized scanning.

## 📚 Documentation

- [Usage guide](docs/USAGE.md): installation, configuration, commands and examples.
- [Scope management](docs/SCOPE.md): implicit modes, files, exclusions and CI.
- [Architecture](docs/ARCHITECTURE.md): DAG, artifacts, central filtering and outputs.
- [Contribution guide](AGENTS.md): repository structure, style and validations.

> **Français** : [Documentation en français](docs/fr/README.md) · **中文**：[中文文档](docs/zh/README.md)

## 🚀 Key Features

- **Artifact-driven pipeline**: Modules communicate through artifacts in an ordered way (e.g. `subfinder` output automatically feeds `dnsx` and `httpx`), with parallel execution per DAG wave.
- **Strict scope validation**: Explicit scope via file, or confirmed implicit scope (`exact` by default, `domain` on request), then filtering of every artifact.
- **Multi-target engagements**: `--targets file` runs a profile against many targets (one per line, comments and blanks ignored); each target gets its own scope validation, run directory and report, and a failing target does not abort the rest.
- **Interactive wizard**: a bare `scanforge run` on a terminal asks for the missing target and profile instead of failing.
- **Proxy integration (Caido / Burp Suite)**: `--proxy` routes HTTP traffic of the relevant modules through your interception proxy for manual triage/replay.
- **Authenticated scanning**: `-H/--header` (repeatable) injects headers/cookies (session, bearer token) into every HTTP request issued.
- **JavaScript secrets scanner**: the `jssecrets` module fetches crawled `.js` files and detects exposed API keys/tokens/creds, public cloud buckets, internal hosts, emails, sensitive API endpoints and accessible source maps; the `jsverify` module then replays the generated PoC payloads in a headless browser and reports executed, sink-reached or not-observed verdicts.
- **Visual snapshots**: the `screenshot` module captures screenshots of alive URLs via `httpx`, listed in the report.
- **Tech-to-CVE correlation**: `techcve` matches detected technologies and versions against a bundled dataset with real CVSS base scores from NVD.
- **Fully configurable Nuclei**: severity, tags, rate-limit, overall timeout, custom templates and template updates via dedicated flags.
- **Parallelized Nmap**: bounded worker pool (`--nmap-concurrency`) instead of sequential host-by-host scans.
- **Real-time progress**: spinner per active module during the scan (visible by default, not only in `--verbose`), findings surfaced live as modules discover them, module warnings replayed after the TUI, colored tables for `plan`/`doctor`, and a summary panel at the end of the run.
- **Webhook notifications**: at the end of each run, a summary is posted to a Slack/Discord/Teams webhook configured in `scanforge.yaml`.
- **Run comparison & export**: `scanforge diff` lists what changed between two runs of the same target (assets, ports, vulnerabilities); `scanforge export` serializes a run as SARIF 2.1.0 (GitHub/GitLab code scanning) or DefectDojo generic findings.
- **Dry-Run mode**: Preview the commands that will be launched and the generated files before making any network request.
- **Diagnostic tool (Doctor)**: Instantly check whether your local dependencies are installed and configured for the selected profile.
- **Consolidated reports**: Automatically generates a unified risk model in `report.json` and `report.md` formats.

---

## 🛠️ Supported Tools

ScanForge centralizes and orchestrates **14 external security tools** and **6 native modules**:

External tools:

1. **subfinder** (Subdomain discovery)
2. **shuffledns** (DNS bruteforce, module `dnsbrute`; results merged into `dnsx`)
3. **dnsx** (Active DNS resolution)
4. **httpx** (HTTP probing, technology detection and screenshots)
5. **naabu** (Ultra-fast port scanner)
6. **nmap** (Accurate port scanning and service detection, run in parallel)
7. **whatweb** (Web technology fingerprinting)
8. **wafw00f** (Web Application Firewall detection)
9. **katana** (Web resource crawling)
10. **ffuf** (Directory and file fuzzing)
11. **nuclei** (Template-based vulnerability scanner)
12. **gau** (Passive collection of historical URLs)
13. **tlsx** (TLS certificate and protocol enrichment)
14. **chromium** (Headless browser used by the `jsverify` module)

Native modules (no external binary):

- **jssecrets** — analyzes JS crawled by `katana` to detect secrets, cloud buckets, internal hosts, emails and exposed source maps
- **jsverify** — replays `jssecrets` PoC payloads in a headless browser (payload injected via URL parameters, fragment and `postMessage`) and reports executed, sink-reached, or not-observed verdicts
- **attacksurface** — consolidates alive hosts, crawled URLs, fuzzed paths and JS-discovered endpoints into one attack surface list for downstream scanners
- **techcve** — correlates detected technologies and versions with known CVEs from a bundled dataset (real CVSS base scores from NVD)
- **httpcheck** — checks HTTP security headers (CSP, HSTS, clickjacking, cookies) on the discovered attack surface
- **payloadgen** — generates contextual wordlists (API paths, parameters, per-technology endpoints) from scan findings

`httpx`, `nuclei`, `katana`, `ffuf`, `whatweb`, `wafw00f`, `subfinder`, `gau`, `jssecrets`, `jsverify`, `httpcheck` and `screenshot` support `--proxy` and `-H/--header` to route traffic through Caido/Burp and scan in authenticated mode.

---

## 📦 Simple Installation (Hassle-Free)

Like mainstream tools (nuclei, subfinder...), ScanForge is distributed as **prebuilt binaries** via GitHub Releases: no compilation, no Go required.

### Option 1: One-liner (Recommended)

**Linux / macOS / Git-Bash:**

```bash
curl -fsSL https://raw.githubusercontent.com/MikeRoss27/scanforge/main/install.sh | bash
```

The script detects your OS/architecture, downloads the latest version, verifies its SHA-256 checksum and installs it in `~/.local/bin`.

**Windows (PowerShell):**

```powershell
Invoke-Expression (Invoke-RestMethod https://raw.githubusercontent.com/MikeRoss27/scanforge/main/install.ps1)
```

The installer places the binary in `%LOCALAPPDATA%\Programs\scanforge` and automatically adds the directory to the user PATH.

**Specific version or custom directory:**

```bash
curl -fsSL https://raw.githubusercontent.com/MikeRoss27/scanforge/main/install.sh | bash -s -- --version v0.1.0 --dir /usr/local/bin
```

### Option 2: Full installation (binary + scan tools)

ScanForge orchestrates external tools (nmap, nuclei, subfinder, httpx, ...). `--full` installs dependencies that have a reliable unattended method (a recent Go remains required on Debian/Ubuntu and Windows):

```bash
curl -fsSL https://raw.githubusercontent.com/MikeRoss27/scanforge/main/install.sh | bash -s -- --full
```

From a clone of the repository, the local scripts do the same:

```bash
chmod +x install.sh && ./install.sh --full   # Linux / macOS
.\install.ps1 -Full                           # Windows (PowerShell)
```

- Arch uses only official pacman packages (`nmap`, `chromium`, `go`, `python-pipx`, `base-devel`) and never runs `pacman -Syu`. Pinned Go tools use `go install`, `wafw00f` uses pipx, and verified upstream artifacts provide massdns and the DNS wordlist. WhatWeb remains manual/AUR-only; no AUR helper is assumed.
- Debian/Ubuntu installs packages available in the current apt release, builds verified massdns when needed, and never modifies system Python with global pip.
- macOS uses Homebrew, pinned Go tools and pipx; WhatWeb and a Chrome-family browser may remain manual.
- Native Windows installs pinned Go tools and uses pipx when available. Nmap, massdns and WhatWeb remain manual; WSL or Docker is recommended for profiles that need them.

The final verification reports anything still missing. `scanforge doctor --profile NAME` then gives profile-specific status and installation guidance.

### Option 3: Docker (Zero local installation)

If you don't want to install Go or the other tools on your host system, use Docker. Runtime tools, massdns, Chromium and a verified pinned DNS wordlist are included.

```bash
# With docker-compose
docker-compose run scanforge run target.com --profile web

# Manually with Docker
docker build -t scanforge .
docker run -v $(pwd):/workspace scanforge run target.com --profile web
```

---

## 🚦 Quick Start Guide

### 1. Initialize the project

Generate the default configuration files in your current directory:

```bash
scanforge init
```

This creates:

- `scanforge.yaml`: Lets you configure tool paths and modify/define profiles.
- `scope.txt`: Optional template to keep a reusable perimeter. You can delete it; ScanForge will then propose a minimal implicit scope to confirm.

### 2. Validate the environment

Check that all tools required for your scan profile are installed and accessible:

```bash
scanforge doctor --profile web
```

### 3. Launch a Scan

Without an applicable scope file, ScanForge derives a minimal scope from the
target, displays it and asks for explicit confirmation before creating the run:

```bash
scanforge run example.com --profile web
```

On a terminal, a bare `scanforge run` (no target, no profile) opens an
interactive wizard that asks for both. To include the domain and its
subdomains, add rules or exclude some:

```bash
scanforge run example.com --scope-mode domain \
  --scope-add api.other.test --exclude admin.example.com
```

`--scope file.txt` remains authoritative and is never silently replaced if it
rejects the target. To avoid any ambiguity, it does not combine with
`--scope-mode`, `--scope-add` or `--exclude`. An explicit or configured file
requires no additional confirmation. For an implicit scope in CI or without a
TTY, inspect `scanforge plan` first, then confirm the intent with
`--confirm-scope`.

To test without sending any request:

```bash
scanforge run example.com --profile web --dry-run --confirm-scope
```

With an implicit scope, dry-run also requires confirmation: it performs no
network requests, but formalizes the authorized perimeter.

Preview the validated pipeline before creating a run:

```bash
scanforge plan example.com --preset deep
```

The `scanforge scan` command is a more direct alias of `scanforge run`:

```bash
scanforge scan example.com --preset safe
```

### 4. Multi-target engagements

`run` and `plan` accept a targets file instead of a single positional target:

```bash
scanforge plan --targets targets.txt --preset web
scanforge run --targets targets.txt --preset web --confirm-scope
```

The file holds one target per line (`#` comments and blank lines ignored).
`--targets` is exclusive with a positional target.

### 5. Compare runs and export findings

`scanforge diff` reconsolidates two run directories and lists what changed —
assets, ports and vulnerabilities that appeared or disappeared:

```bash
scanforge diff runs/example.com/2026-08-09_10-00-00 runs/example.com/2026-08-10_10-00-00
scanforge diff runs/example.com/2026-08-09_10-00-00 runs/example.com/2026-08-10_10-00-00 --json
```

`scanforge export` serializes the consolidated report for third-party tools:

```bash
scanforge export runs/example.com/2026-08-10_10-00-00 --format sarif          # GitHub/GitLab code scanning
scanforge export runs/example.com/2026-08-10_10-00-00 --format defectdojo     # import-scan "Generic Findings Import"
```

### 6. API keys and updates

Some tools (subfinder, nuclei, ...) benefit from API keys. Manage them with
`scanforge auth`:

```bash
scanforge auth set shodan <API_KEY>
scanforge auth list
scanforge auth sync
```

Update the binary (and optionally the external tools) with `scanforge update`:

```bash
scanforge update            # binary only (requires Go)
scanforge update --tools    # binary + external tools
```

---

## 🕵️ Proxy, authentication and Nuclei settings

For real-world penetration testing, route traffic through Caido (or Burp
Suite) and inject an authenticated session:

```bash
scanforge run app.example.com --profile web \
  --proxy http://127.0.0.1:8080 \
  -H "Cookie: session=..." \
  --nuclei-tags cve,exposure --nuclei-severity critical,high \
  --nuclei-update-templates \
  --nuclei-include-custom \
  --ffuf-wordlist /usr/share/wordlists/dirb/big.txt \
  --nmap-concurrency 6
```

- `--proxy`: HTTP/SOCKS proxy for the modules that speak HTTP.
- `-H/--header` (repeatable): raw header `"Name: Value"` added to every request.
- `--nuclei-severity`, `--nuclei-exclude-severity`, `--nuclei-tags`, `--nuclei-exclude-tags`, `--nuclei-rate-limit`, `--nuclei-templates`, `--nuclei-update-templates`: fine-grained control of the vulnerability scanner.
- `--nuclei-timeout`: overall time limit for a nuclei run, e.g. `45m` (default 30m; raise it for slow proxies or large target lists).
- `--nuclei-headless`: enable nuclei headless mode (browser-based templates).
- `--nuclei-include-custom`: also run the 40+ ScanForge templates bundled in `templates/` (cloud metadata endpoints, exposed admin panels and dashboards, CORS misconfigurations, XXE, SSRF, debug endpoints, ...); located via `SCANFORGE_TEMPLATES_DIR`, `./templates` or next to the binary.
- `--ffuf-wordlist`, `--ffuf-filter-codes`: override the ffuf wordlist (default `/usr/share/wordlists/dirb/common.txt`) and filter out status codes.
- `--nmap-concurrency`: number of simultaneous nmap scans (default 4); lower it to stay discreet on a sensitive engagement.

### Webhook notifications

Set `webhook.url` in `scanforge.yaml` to receive a run summary on Slack,
Discord or Teams at the end of every scan:

```yaml
webhook:
  url: https://example.com/hooks/your-webhook-url
```

The payload is a generic JSON document with a `text` field, so every major
webhook receiver renders a readable message (target, profile, status, assets,
ports, vulnerabilities by severity, run directory).

---

## 📊 Built-in Profiles and Presets

| Name | Modules | Usage |
| --- | --- | --- |
| `safe` | subfinder, dnsx, httpx, tlsx | Light exposure check. |
| `recon` | subfinder, dnsbrute, gau, dnsx, httpx, tlsx | Inventory enriched with historical URLs and DNS bruteforce. |
| `passive` | subfinder, dnsx, httpx | Minimal historical pipeline. |
| `ports` | subfinder, dnsx, naabu, nmap | Open ports then service validation. |
| `web` | subfinder, dnsbrute, dnsx, httpx, whatweb, wafw00f, katana, jssecrets, jsverify, attacksurface, techcve, httpcheck, payloadgen, screenshot, nuclei | Application analysis: attack-surface consolidation, JS secrets + headless verification, screenshots, tech-to-CVE correlation, header checks and payload generation. |
| `vuln` | subfinder, dnsbrute, dnsx, httpx, tlsx, katana, jssecrets, attacksurface, techcve, nuclei | Targeted vulnerability detection (tech-to-CVE + templates). |
| `deep` | All modules | Full and noisy pipeline. |
| `full` | All modules | Full profile, history-compatible. |

Use `--preset safe` or `--profile safe` interchangeably. Before any active
profile, always review its DAG with `scanforge plan`.

---

## 📂 Final Report Structure

At the end of each scan, a timestamped folder is created under `./runs/`. In addition to the raw logs of each tool, ScanForge generates:

- `report.json`: Structured model of assets, ports, technologies and vulnerabilities.
- `report.md`: Readable synthetic report.
- `00_meta/manifest.json`: Run status, modules, artifacts and scope metadata.
- `00_meta/commands.log`: External commands prepared or executed.
- `00_meta/effective-scope.txt`: Canonical copy of the scope actually applied, with its source and mode recorded in the manifest.
- `00_meta/scope-rejections.jsonl`: Out-of-scope values rejected, when any.
- `04_surface/attack-surface.txt`: Consolidated candidate URLs for scanning (module `attacksurface`).
- `04_payloads/`: Generated wordlists for api paths, endpoints, parameters and per-technology endpoints (module `payloadgen`).
- `04_web/screenshots/`: PNG snapshots of alive URLs (module `screenshot`).
- `06_vulns/js-secrets.jsonl`: Secrets, cloud buckets, internal hosts, emails and source maps detected in crawled JS (module `jssecrets`).
- `06_vulns/js-payloads.txt`: PoC payloads generated from the JS secrets (module `jssecrets`).
- `06_vulns/js-verified.jsonl`: Headless-browser verdicts (executed, sink-reached, not-observed) for the JS payloads (module `jsverify`).
- `06_vulns/cve-findings.jsonl`: Vulnerable versions correlated from fingerprints (module `techcve`).
- `06_vulns/http-checks.jsonl`: Missing security headers and cookie flags (module `httpcheck`).
- `06_vulns/nuclei.jsonl`: Raw nuclei findings (module `nuclei`).

> ScanForge must only be used on assets for which you have explicit
> authorization.
