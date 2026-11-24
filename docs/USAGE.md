# Usage guide

## Installation

### One-liner (prebuilt binary, no Go)

```bash
curl -fsSL https://raw.githubusercontent.com/MikeRoss27/scanforge/main/install.sh | bash
```

```powershell
Invoke-Expression (Invoke-RestMethod https://raw.githubusercontent.com/MikeRoss27/scanforge/main/install.ps1)
```

### With the external tools (requires Go)

```bash
curl -fsSL https://raw.githubusercontent.com/MikeRoss27/scanforge/main/install.sh | bash -s -- --full
```

From a clone of the repository, the local scripts do the same:

```bash
./install.sh --full
```

```powershell
.\install.ps1 -Full
```

On Arch, `--full` uses `pacman -S --needed` only for official packages and never performs a full system upgrade. Pinned Go tools, isolated pipx and verified upstream artifacts cover the remaining automated dependencies; WhatWeb remains manual/AUR. No global pip install is used, preserving PEP 668 compatibility. The final verification and `scanforge doctor --profile NAME` identify anything still missing.

You can also build the binary locally:

```bash
make build      # or: go build -o scanforge ./cmd/scanforge
```

## Development commands

Go 1.27.x is required to build from source (see `go.mod`).

From a clone of the repository, the `Makefile` wraps the Go toolchain. Most
useful targets:

| Command | Purpose |
| --- | --- |
| `make dev` / `make run` | Run the CLI via `go run` without building; pass arguments with `ARGS="plan example.com --preset deep"` |
| `make test` / `make race` | Test suite (fast / with the race detector) |
| `make check` | Pre-push gate: formatting check, `go vet`, golangci-lint and tests |
| `make cover` | Tests with coverage report and per-function summary |
| `make fmt` / `make fmt-check` | Format the code / list unformatted files without rewriting them |
| `make vet` / `make lint` | Static analysis; `make tools` installs the golangci-lint version pinned by CI |
| `make tidy` | Clean up `go.mod` / `go.sum` |
| `make clean` | Remove the binary and `coverage.out` |

## Configuration

`scanforge init` creates `scanforge.yaml`, an optional `scope.txt` and the
`runs/` directory. The configuration is looked up in this order:

1. `--config path.yaml`
2. `SCANFORGE_CONFIG` environment variable
3. `./scanforge.yaml`

Executable paths are configured under `tools`. Built-in profiles can be
overridden; the `web`, `vuln`, `deep` and `full` presets chain an
attack-surface consolidation step (`attacksurface`), technology-to-CVE
correlation (`techcve`), HTTP security header checks (`httpcheck`) and dynamic
payload wordlist generation (`payloadgen`):

```yaml
workspace: runs
default_profile: safe

tools:
  subfinder: /opt/bin/subfinder

profiles:
  internal-web:
    - subfinder
    - dnsx
    - httpx
    - nuclei
```

Per-module time limits are set under `module_timeouts` with Go durations. A
module exceeding its limit is killed and reported as failed, and its
dependents are skipped; unset modules keep their own default:

```yaml
module_timeouts:
  nuclei: 45m
  katana: 20m
```

Global resource limits are set under `limits` (all optional, `0`/unset means
unlimited). They are enforced by a scheduler shared by every module, count
launched commands (not HTTP requests) and are overridden by the matching
`run` flags `--concurrency`, `--rps`, `--max-requests` and
`--command-timeout`:

```yaml
limits:
  concurrency: 4          # commands running at once
  rps: 10                 # command launches per second (also lowers tools' own rate flags)
  max_requests: 500       # command budget per run; later commands fail once spent
  command_timeout: 20m    # upper bound for every command's timeout
```

The `ai` section configures the LLM backend used by `scanforge triage`. Any
server exposing the OpenAI-compatible chat completions API works (llama.cpp,
vLLM, Ollama, LM Studio, ...). When the section is omitted, triage runs in
deterministic-only mode (deduplication and grouping without a model):

```yaml
ai:
  base_url: http://127.0.0.1:8080/v1
  model: qwen3.5-9b
  api_key: ""        # optional for local servers
  timeout: 5m
  temperature: 0.1   # low values keep triage output stable
```

## Built-in nuclei templates

`--nuclei-include-custom` adds the templates bundled in the `templates/`
directory of this repository to the nuclei run (`spring-actuator-exposed`,
`swagger-openapi-exposed`, `cors-wildcard-credentials`,
`go-debug-endpoints-exposed`, `wordpress-debug-log-exposed`, `wordpress-config-backup-exposed`, `wordpress-install-exposed`, `wordpress-readme-exposed`). They are located
via `SCANFORGE_TEMPLATES_DIR`, then the working directory (`./templates`) and
finally the executable directory.

By default nuclei runs with `-as` (automatic scan): it picks templates from
each host's detected technology instead of firing the full template catalog
at every host, and uses nuclei's own default rate limit (150 req/s). Pass
`--nuclei-tags`, `--nuclei-templates`, or `--nuclei-full-scan` to run every
template against every host instead (slower; raise `--nuclei-timeout` to
match). `--nuclei-rate-limit` overrides the rate limit either way.

`ffuf` fans a separate process out per alive host (bounded by an internal
concurrency cap, same tradeoff as `nmap`) instead of fuzzing every host from
one invocation — each host's auto-calibration (`-ac`/`-ach`) only learns
that host's own wildcard/soft-404 signature reliably when it runs alone.

## WordPress (wp)

`scanforge run example.com --preset wp` runs the WordPress engagement chain:
`subfinder → dnsbrute → dnsx → httpx → whatweb → wpdetect → wpplugins → wpthemes → wpusers → wpexposure → wpxmlrpc → wpcve → techcve → httpcheck → attacksurface → nuclei → screenshot`.

- Detection is **passive by default**: plugin/theme versions are read from crawled assets (`?ver=`), exposed `readme.html` files, the REST index and the RSS feed. Nothing fuzzable happens without your say-so.
- `--wp-detection-mode mixed` additionally reads `readme.txt` for the passively detected slugs (versions + confirmation). `--wp-detection-mode aggressive --wp-wordlist slugs.txt` probes plugin/theme slugs from a bundled top list (or your own file, one slug per line) for the closest wpscan parity. Aggressive mode can be noisy; tune it on a low-noise engagement.
- `--wp` adds the WordPress chain to any other profile (`scanforge run example.com --profile web --wp`).
- `wpcve` correlates core/plugin/theme versions with the bundled advisory dataset (offline; verified against NVD, see `internal/modules/wpcve/cves_wp.yaml`). No API key required.
- `wpbrute` (credential probe against enumerated users) is **OFF everywhere by default** and only runs with all of: `--wp-bruteforce` + `--confirm-scope` (implicit scopes) + `--wp-passwords <wordlist>`. It caps at `--wp-bruteforce-max` attempts per user (default 100), stops on the first success or on any lockout signal, and refuses to run when `wpusers` produced no usernames. No password list is bundled.
- `scanforge doctor --profile wp` reports the bundled wordlists/dataset and the external tooling availability.
- Without `--wp`, `scanforge run` still runs a quick passive WordPress probe against the confirmed target (same signals as `wpdetect`, capped at 8s) right after scope confirmation. If it looks like WordPress and the session is an interactive terminal, it asks whether to add the chain to this run; in a non-interactive context (CI, scripts, `--dry-run`) it only logs the detection and leaves the run unchanged.

## Recommended flow

First check the dependencies and the plan:

```bash
scanforge doctor --profile safe
scanforge plan example.com --preset safe
```

Then launch the run. Without an applicable file, the implicit scope is
displayed and confirmed before any folder is created:

```bash
scanforge run example.com --preset safe
```

To inspect the commands without executing them:

```bash
scanforge run example.com --preset ports --dry-run
```

Dry-run requires the same confirmation when it uses an implicit scope. In a
non-interactive terminal:

```bash
scanforge plan example.com --scope-mode domain
scanforge run example.com --scope-mode domain --confirm-scope
```

## Useful commands

| Command | Purpose |
| --- | --- |
| `scanforge init` | Creates the initial configuration. |
| `scanforge doctor --profile NAME` | Checks the tools of a profile. |
| `scanforge plan TARGET` | Displays the scope and the DAG waves. |
| `scanforge run TARGET` | Runs an authorized profile. |
| `scanforge scan TARGET` | Alias of `run`. |
| `scanforge diff RUN1 RUN2` | Delta (assets/ports/vulns) between two runs of the same target. |
| `scanforge export RUN --format sarif\|defectdojo` | Exports a run report for CI (SARIF) or DefectDojo (generic findings). |
| `scanforge assets TARGET [--new\|--gone] [--json]` | Lists the per-target asset history (`runs/<target>/assets.jsonl`) used by `--incremental` (see `INCREMENTAL.md`). |
| `scanforge resume RUN-ID` | Resumes an interrupted run, re-running only what did not complete or whose inputs changed (see `RESUME.md`). |
| `scanforge status RUN-ID [--json]` | Shows each module's checkpoint state and the run's scope provenance. |
| `scanforge runs list [--target T] [--json]` | Lists the runs of the workspace, newest first. |
| `scanforge workflow validate FILE.yaml` | Validates a YAML workflow without running anything (see `WORKFLOWS.md`). |
| `scanforge intel update\|status` | Downloads / inspects the local NVD, CISA KEV and EPSS cache used by `techcve`. |
| `scanforge mcp` | Serves ScanForge to AI agents over MCP on stdio (see `MCP.md`). |
| `scanforge api` | Serves the run store over a local HTTP JSON API (see `API.md`). |
| `scanforge triage RUN` | Groups, groups and (with an `ai:` backend) analyzes the findings of a run. |
| `scanforge auth` | Manages the keys required by some tools. |
| `scanforge benchmark run LAB\|--all` | Maintainer tool: runs the real pipeline against bundled vulnerable labs and scores detection against expectations. |
| `scanforge version` | Displays the binary version. |

See `scanforge <command> --help` for the exact list of options.

## Resume, workflows, intel and agent access

Detailed guides (written in French): [RESUME](RESUME.md),
[WORKFLOWS](WORKFLOWS.md), [MCP](MCP.md), [API](API.md).

```bash
scanforge runs list --target example.com
scanforge status example.com/2026-08-18_10-00-00
scanforge resume example.com/2026-08-18_10-00-00
```

Runs are checkpointed in `00_meta/manifest.json`; `resume` skips modules that
completed with identical inputs, reuses the stored effective scope and can
never widen it. `--proxy` and `--header` are not stored: pass them again.

```bash
scanforge workflow validate workflows/web-recon.yaml
scanforge plan example.com --workflow workflows/web-recon.yaml
scanforge run example.com --scope scope.txt --workflow workflows/web-recon.yaml --rps 20
```

A workflow replaces the profile (`--workflow` is exclusive with `--profile`,
`--preset` and `--wp`); it compiles to the same DAG, cannot run shell commands
and keeps the same scope enforcement.

`scanforge run --events` (experimental, off by default) also emits discovery
events (subdomains become `DNS_NAME`) to `00_meta/events.jsonl`; every event is
scope-gated before it is recorded.

`scanforge intel update` is the only command that downloads vulnerability
intelligence (NVD, CISA KEV, EPSS; `--source nvd|kev|epss` limits it);
`scanforge intel status` inspects the cache offline. Scans never touch the
network for intel. `techcve` uses the cache when present and labels matches
`exact-cpe-range`, `version-range` or `name-only` (name-only is never
confirmed). Set `SCANFORGE_NVD_API_KEY` for a higher NVD rate limit; the cache
lives in `SCANFORGE_INTEL_DIR` or `~/.cache/scanforge/vulnintel`.

```bash
scanforge mcp                                    # read-only MCP over stdio
scanforge mcp --allow-active --scope scope.txt   # also allow scope-bound active scans
scanforge api --listen 127.0.0.1:8787 --token-file ./token
```

Active scans through MCP/API are disabled by default and need `--allow-active`
together with a strict `--scope` file; every active call is audit-logged. The
API listens on loopback only unless `--unsafe-bind` is given.

**Secrets rule:** secret values leaked by the target (AWS keys, tokens found in
JavaScript...) stay in full in findings, since they are the evidence for a
report. Only the operator's own credentials (API keys from `auth`, the `ai:`
key, proxy/header values passed to a scan) are masked in logs and in API/MCP
output.

## Incremental scans and recursive discovery

Detailed guides (written in French): [INCREMENTAL](INCREMENTAL.md),
[RECURSIVE](RECURSIVE.md).

After every completed (non dry-run) run, ScanForge appends the observed assets
to `runs/<target>/assets.jsonl` (`new`, `unchanged`, `changed`, `gone`).
`--incremental` makes nuclei, ffuf, katana and jssecrets look only at new or
changed URLs; history entries are re-filtered against the current scope, and
everything is treated as new when the scope or a tool version changed.
`resume` of an incremental run stays incremental.

```bash
scanforge run example.com --preset web --incremental
scanforge assets example.com --new
scanforge assets example.com --gone --json
```

`--recursive` (off by default) emits discovery events from the artifacts of
existing modules: a new in-scope name found late (JS, crawl) gets a bounded
`dnsx` then `httpx` pass, a new live URL a `katana` depth-1 pass. Out-of-scope
discoveries are dropped and logged to `00_meta/scope-rejections.jsonl`;
follow-up commands go through the scheduler and count against
`--max-requests`. Events land in `00_meta/events.jsonl` and follow-up output
in `07_recursive/`.

```bash
scanforge run example.com --preset web --recursive
scanforge run example.com --preset web --recursive --recursive-depth 3 --recursive-budget 100
```

```yaml
recursive:
  enabled: false
  depth: 2     # maximum discovery depth (default 2)
  budget: 200  # maximum follow-up commands per run (default 200)
```

In `deep`/`full` (and any profile with `naabu`), `httpx` now runs after
`naabu` and also probes the scope-filtered non-standard `host:port` targets
(8080, 8443, 3000...), so the downstream web modules cover services beyond
80/443.

## Triage of findings

`scanforge triage <run>` projects the consolidated report into canonical
findings, computes deterministic relations (duplicates, shared CVE, shared
endpoint, same asset) and writes the result under `<run>/triage/`:

```text
triage/manifest.json    provenance: model, prompt version, input digest
triage/relations.json   deterministic finding-to-finding relations
triage/insights.json    insights (dedup groups + validated LLM insights)
triage/report.md        human-readable summary
```

With an `ai:` backend configured, the model receives a deliberately reduced
projection of the findings (truncated evidence, no raw tool output) and its
insights are validated before being stored: any insight referencing an
unknown finding ID, CVE or evidence string is rejected. The model can
interpret findings, never create them. Re-running with unchanged input hits
the cache (0 inference); `--force` bypasses it:

```bash
scanforge triage runs/example.com/2026-08-19T10:00:00Z
scanforge triage runs/example.com/2026-08-19T10:00:00Z --force
scanforge triage runs/example.com/2026-08-19T10:00:00Z --model qwen3.5-9b
```

## Multi-target engagements

`run` and `plan` accept a targets file instead of a single positional target.
Each target gets its own scope validation, run directory and report under
`runs/<target>/`; a failing target does not abort the rest of the engagement.

```bash
scanforge plan --targets targets.txt --preset web
scanforge run --targets targets.txt --preset web --confirm-scope
```

The file holds one target per line (comments with `#` and blank lines
ignored). `--targets` is exclusive with a positional target.

## Comparing runs and exporting

`scanforge diff` reconsolidates two run directories and lists what changed —
assets, ports and vulnerabilities that appeared or disappeared (a quick
periodic ASM loop without any infrastructure):

```bash
scanforge diff runs/example.com/2026-08-09_10-00-00 runs/example.com/2026-08-10_10-00-00
scanforge diff runs/example.com/2026-08-09_10-00-00 runs/example.com/2026-08-10_10-00-00 --json
```

`scanforge export` serializes the consolidated report for third-party tools:

```bash
scanforge export runs/example.com/2026-08-10_10-00-00 --format sarif          # GitHub/GitLab code scanning
scanforge export runs/example.com/2026-08-10_10-00-00 --format defectdojo     # import-scan "Generic Findings Import"
```
