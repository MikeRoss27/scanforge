# ScanForge

ScanForge is a simple Go CLI for authorized pentest and recon workflows.

It does not replace tools like `subfinder`, `httpx`, `nuclei`, `nmap`, or `ffuf`.
It orchestrates them in a clean, reproducible pipeline and stores every run in an organized folder.

## Status

Early development.

Current features:

- Go CLI with Cobra
- Scope validation
- Dry-run mode
- Timestamped run directories
- Manifest generation
- Command logging
- Modular scan architecture
- `subfinder` module
- `httpx` module
- `nuclei` module
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

## Usage

Create a scope file:

```txt
example.com
*.example.com
```

Run a dry-run scan:

```bash
go run ./cmd/scanforge run example.com --scope scope.example.txt --profile passive --dry-run
```

Run the web profile in dry-run mode:

```bash
go run ./cmd/scanforge run example.com --scope scope.example.txt --profile web --dry-run
```

Example output:

```txt
ScanForge run
Target:  example.com
Profile: web
Scope:   scope.example.txt
Dry run: true
Output:  runs/example.com/2026-06-28_20-11-34

$ subfinder -d example.com -silent
$ httpx -l runs/example.com/2026-06-28_20-11-34/01_subdomains/subfinder.txt -silent -json -status-code -title -tech-detect
$ nuclei -l runs/example.com/2026-06-28_20-11-34/02_http/alive.txt -severity low,medium,high,critical -rate-limit 10 -jsonl

Done.
```

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
  -> internal/scope
  -> internal/storage
  -> internal/orchestrator
  -> internal/modules
  -> internal/runner
```

Main packages:

```txt
internal/cli           CLI commands
internal/app           Application layer
internal/scope         Scope parser and matcher
internal/storage       Run directory and manifest management
internal/orchestrator  Profile resolution and module execution
internal/modules       Tool modules
internal/runner        External command execution
```

## Safety

ScanForge is intended only for authorized testing.

Built-in safety rules:

- Scope file is required.
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
- `doctor` command
- Config file support
- Better terminal output
- More parser tests

Later:

- HTML reports
- SQLite run index
- Diff between runs
- Plugin system
- TUI mode

## License

MIT
