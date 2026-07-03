# ScanForge

ScanForge is a simple Go CLI for authorized pentest and recon workflows.

It does not replace tools like `subfinder`, `httpx`, `nuclei`, `nmap`, or `ffuf`.
It orchestrates them in a clean, reproducible pipeline and stores every run in an organized folder.

## Status

**v0.0.1 released**

Current features:

- Go CLI with Cobra
- Scope validation
- Dry-run mode
- Timestamped run directories
- Manifest generation
- Command logging
- Modular scan architecture
- YAML configuration (`scanforge.yaml`)
- `scanforge init` for local setup
- `scanforge doctor` for dependency checks
- `scanforge version` with build metadata
- `subfinder`, `httpx`, and `nuclei` modules
- Parser tests for normalized outputs

## Philosophy

ScanForge is built around a simple idea:

> Keep the scanner logic modular, keep the workflow reproducible, and keep the output readable.

Each module wraps one external tool.
The orchestrator decides which modules run for a given profile.
The runner executes commands with support for dry-run, timeout, stdout files, and stderr files.

## Current profiles

### passive

```txt
subfinder -> httpx
```

### web

```txt
subfinder -> httpx -> nuclei
```

## Install

### From source

Clone the repository:

```bash
git clone https://github.com/MikeRoss27/scanforge.git
cd scanforge
```

Build:

```bash
go build -o bin/scanforge ./cmd/scanforge
```

Run:

```bash
./bin/scanforge --help
```

On Windows PowerShell:

```powershell
go run ./cmd/scanforge --help
```

### From GitHub Release

Download the archive for your platform from the [latest release](https://github.com/MikeRoss27/scanforge/releases/latest):

- Linux: `scanforge_0.0.1_linux_amd64.tar.gz` or `scanforge_0.0.1_linux_arm64.tar.gz`
- macOS: `scanforge_0.0.1_darwin_amd64.tar.gz` or `scanforge_0.0.1_darwin_arm64.tar.gz`
- Windows: `scanforge_0.0.1_windows_amd64.zip`

Verify checksums using the bundled `.sha256` file or `checksums.txt` from the release page.

## Quick start

Initialize local files:

```bash
scanforge init
```

Edit `scope.txt` with your authorized targets, then verify your environment:

```bash
scanforge doctor
scanforge doctor --profile web
```

Run a dry-run scan:

```bash
scanforge run example.com --scope scope.txt --profile passive --dry-run
```

Run the web profile in dry-run mode:

```bash
scanforge run example.com --scope scope.txt --profile web --dry-run
```

Example output:

```txt
ScanForge run
Target:  example.com
Profile: web
Scope:   scope.txt
Dry run: true
Output:  runs/example.com/2026-06-28_20-11-34

$ subfinder -d example.com -silent
$ httpx -l runs/example.com/2026-06-28_20-11-34/01_subdomains/subfinder.txt -silent -json -status-code -title -tech-detect
$ nuclei -l runs/example.com/2026-06-28_20-11-34/02_http/alive.txt -severity low,medium,high,critical -rate-limit 10 -jsonl

Done.
```

## Configuration

ScanForge loads configuration from (in order):

1. `--config /path/to/scanforge.yaml`
2. `SCANFORGE_CONFIG` environment variable
3. `./scanforge.yaml` in the current directory
4. Built-in defaults if no file is found

Example `scanforge.yaml`:

```yaml
config_version: 1
workspace: runs
default_profile: passive
default_scope: scope.txt

tools:
  subfinder: subfinder
  httpx: httpx
  nuclei: nuclei

profiles:
  passive:
    - subfinder
    - httpx
  web:
    - subfinder
    - httpx
    - nuclei
```

Run `scanforge init` to generate this file locally.

## Run output structure

Each scan creates a timestamped directory:

```txt
runs/
└── example.com/
    └── 2026-06-28_20-11-34/
        ├── 00_meta/
        │   ├── commands.log
        │   ├── manifest.json
        │   ├── subfinder.stderr.log
        │   ├── httpx.stderr.log
        │   └── nuclei.stderr.log
        ├── 01_subdomains/
        │   └── subfinder.txt
        ├── 02_http/
        │   ├── httpx.jsonl
        │   └── alive.txt
        ├── 03_ports/
        ├── 04_web/
        ├── 05_content/
        └── 06_vulns/
            ├── nuclei.jsonl
            └── findings.json
```

## Architecture

```txt
cmd/scanforge
  -> internal/cli
  -> internal/app
  -> internal/config
  -> internal/scope
  -> internal/storage
  -> internal/orchestrator
  -> internal/modules
  -> internal/runner
  -> internal/doctor
  -> internal/initcmd
```

Main packages:

```txt
internal/cli           CLI commands
internal/app           Application layer
internal/config        YAML configuration
internal/scope         Scope parser and matcher
internal/storage       Run directory and manifest management
internal/orchestrator  Profile resolution and module execution
internal/modules       Tool modules
internal/runner        External command execution
internal/doctor        Dependency and environment checks
internal/initcmd       Local project initialization
```

## Safety

ScanForge is intended only for authorized testing.

Built-in safety rules:

- Scope file is required (via `--scope` or config default).
- Targets outside the scope are rejected.
- Dry-run mode is supported.
- Commands are logged for traceability.
- Outputs are stored per run.
- Aggressive scanning is not enabled by default.

## Development

Format:

```bash
gofmt -w cmd internal
```

Run tests:

```bash
go test ./...
```

Run dry-run example:

```bash
go run ./cmd/scanforge run example.com --scope scope.example.txt --profile web --dry-run
```

## Roadmap

Short-term:

- Markdown report generation
- `nmap` module
- `ffuf` module
- Better terminal output
- More parser tests

Later:

- HTML reports
- SQLite run index
- Diff between runs
- Plugin system
- TUI mode

## License

MIT — see [LICENSE](LICENSE).
