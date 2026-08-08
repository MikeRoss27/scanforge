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
| `scanforge auth` | Manages the keys required by some tools. |
| `scanforge version` | Displays the binary version. |

See `scanforge <command> --help` for the exact list of options.
