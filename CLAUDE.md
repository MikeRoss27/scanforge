# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

ScanForge is a Go CLI that orchestrates external security/recon tools (subfinder, dnsx, httpx, naabu,
nmap, whatweb, wafw00f, katana, ffuf, nuclei, gau, tlsx) plus one native module (`jssecrets`) into a
single authorized pentest/recon pipeline, with strict scope enforcement between every stage.

## Commands

- `go build -o scanforge ./cmd/scanforge` — build the CLI binary.
- `go run ./cmd/scanforge --help` — run without building.
- `go test ./...` — full test suite (same as CI).
- `go test ./internal/orchestrator -run TestOrchestratorSuccess` — run a single focused test.
- `go vet ./...` — static correctness checks.
- `go fmt ./...` — format before committing.
- `docker-compose run scanforge run example.com --profile web` — containerized run (only against
  targets listed in the mounted scope file).

Go 1.25.x is required (see `go.mod`). CI (`.github/workflows/ci.yml`) runs `go test ./...` then
`go build -o scanforge ./cmd/scanforge` on `ubuntu-latest`.

## Architecture

### Artifact-driven DAG pipeline

Every scanner is a `modules.Module` (`internal/modules/module.go`) implementing:
`Name()`, `Description()`, `Requires() []string`, `Produces() []string`, and
`Run(ctx, *RunContext, runner.Executor) (*Result, error)`.

`internal/orchestrator/dag.go` builds a `DAG` from the modules selected by a profile: it rejects
duplicate artifact producers, unresolvable requirements, and dependency cycles at build time.
`internal/orchestrator/orchestrator.go` then executes the DAG in waves — `DAG.NextReady` returns all
modules whose required artifacts are already available, and each wave runs its modules concurrently
via goroutines, waits, then republishes newly available artifacts before computing the next wave.
Wave modules are processed in profile-declared order (not goroutine completion order) so result
ordering and artifact publication stay deterministic. If a wave produces no ready modules (upstream
failure), remaining modules are marked `skipped` rather than aborting the whole run.

Core artifact chains (see `docs/ARCHITECTURE.md`):
```
subfinder → subdomains → dnsx → resolved_hosts
resolved_hosts → httpx → alive_urls
resolved_hosts → naabu → open_ports → nmap
alive_urls → tlsx / whatweb / wafw00f / katana / ffuf / nuclei
target → gau → historical_urls
```
`scanforge plan TARGET --preset deep` prints the validated waves without running anything or
creating a run directory — use it to sanity-check a profile before `run`.

New scanner integrations live in `internal/modules/<tool>/`, satisfy the `modules.Module` interface,
and are wired into `buildRegistry()` in `internal/app/app.go`. Follow the existing modules (e.g.
`internal/modules/dnsx/dnsx.go`) for the pattern: build a `runner.Command`, log it via
`runner.AppendCommandLog`, execute through the injected `runner.Executor` (never exec directly), then
publish outputs with `runCtx.AddArtifact`.

### Scope enforcement (the central security boundary)

Scope is mandatory; the config file (`scope.txt`) is not. `internal/scope/scope.go` implements the
allow/deny logic (exact/domain modes, wildcards, CIDR, `!`-prefixed exclusions). The effective scope
is resolved once per run in `internal/app/scope.go` — either from an explicit `--scope` file (strict,
no fallback) or an implicit scope (`exact` or `domain` mode) that requires interactive or
`--confirm-scope` confirmation before a run directory is even created.

`internal/modules/context.go` (`RunContext.AddArtifact` → `filterArtifact`) is the single choke point
where every line-oriented artifact of type `text` whose name is in `scopedTextArtifacts` (subdomains,
resolved_hosts, alive_urls, crawled_urls, open_ports, historical_urls) gets filtered in place against
`Scope.IsAllowed` before any downstream module can read it. Rejected values never reach a module and
are appended to `00_meta/scope-rejections.jsonl`. When adding a new module that produces one of these
artifact types, no extra wiring is needed — filtering is automatic based on the artifact name.
Modules that consume scope-filtered artifacts should never re-derive targets by other means (e.g.
parsing arbitrary tool output for hosts) that bypass this boundary.

### Execution layer

`internal/runner` defines `Executor` (`Run(ctx, Command) (*CommandResult, error)`) with two
implementations: `NewRealExecutor` (actually shells out) and `NewDryRunExecutor` (records commands
without network access). `App.Run` selects the executor based on `--dry-run`. Modules must always go
through the injected `Executor` rather than calling `os/exec` directly, so dry-run and command
logging stay centralized.

### Layering

`cmd/scanforge/main.go` → `internal/cli` (cobra commands, flag parsing) → `internal/app` (`App.Run`,
`App.Doctor`, `App.Init`; orchestrates config load, scope resolution, run store creation, registry
build, orchestrator invocation, report generation) → `internal/orchestrator` (DAG + wave execution) →
`internal/modules/<tool>` (individual scanner integrations) → `internal/runner` (command execution).

Supporting packages: `internal/config` (YAML config + profile overrides), `internal/profile` (built-in
profile→module-list mappings, see `internal/profile/profile.go` for `safe/recon/passive/web/ports/
vuln/deep/full`), `internal/storage` (`runs/<target>/<timestamp>/` layout + manifest), `internal/report`
(parses per-module outputs into a unified `report.json`/`report.md`), `internal/doctor` (dependency
checks), `internal/auth` (API key management for tools that need them).

### Run output layout

Each run under `runs/<target>/<timestamp>/`:
```
00_meta/       manifest.json, commands.log, effective-scope.txt, scope-rejections.jsonl
01_subdomains/ subfinder + dnsx results
02_http/       httpx probes, tlsx enrichment
03_ports/      naabu results, nmap XML
04_web/        whatweb/wafw00f
05_content/    katana crawl, gau historical URLs, ffuf
06_vulns/      nuclei results, js-secrets.jsonl (from jssecrets)
report.json    normalized findings model
report.md      human-readable summary
```
The manifest records status (`completed`/`partial`/`failed`), per-module results, and scope
provenance (`scope_source`, `scope_mode`) for audit.

## Coding conventions

- Standard `gofmt` formatting; short lowercase package names; `PascalCase` exported, `camelCase`
  internal; lowercase filenames (`commandlog.go`).
- Wrap errors with `%w` for context.
- Unit tests are `*_test.go` beside the code they test, named `TestBehavior`; prefer table-driven
  tests. Use fakes/the dry-run executor instead of invoking real security tools in tests. Fixtures for
  representative tool output go in `testdata/`.
- Commit subjects follow Conventional Commits style (`feat:`, `fix:`, `test:`, `docs:`, `chore:`),
  concise and imperative.

## Notes

- The README and `docs/*.md` are written in French; this repo's user-facing docs are French-first.
- Runtime scan output under `runs/` is gitignored and must not be committed.
- `docker compose run scanforge ...` and any live run must only target hosts explicitly present in
  the mounted/confirmed scope — this is a safety-critical tool for authorized engagements only.
