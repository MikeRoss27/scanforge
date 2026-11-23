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
| `scanforge triage RUN` | Groups, groups and (with an `ai:` backend) analyzes the findings of a run. |
| `scanforge auth` | Manages the keys required by some tools. |
| `scanforge benchmark run LAB\|--all` | Maintainer tool: runs the real pipeline against bundled vulnerable labs and scores detection against expectations. |
| `scanforge version` | Displays the binary version. |

See `scanforge <command> --help` for the exact list of options.

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
