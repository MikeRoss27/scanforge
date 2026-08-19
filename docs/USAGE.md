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

You can also build the binary locally:

```bash
go build -o scanforge ./cmd/scanforge
```

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
`go-debug-endpoints-exposed`, `wordpress-debug-log-exposed`). They are located
via `SCANFORGE_TEMPLATES_DIR`, then the working directory (`./templates`) and
finally the executable directory.

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
