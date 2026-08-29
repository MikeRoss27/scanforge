# Repository Guidelines

## Project Structure & Module Organization

ScanForge is a Go CLI that orchestrates external recon/security tools into a single scope-enforced pipeline. The executable entry point is `cmd/scanforge/main.go`; cobra command definitions live in `internal/cli/`. Core packages under `internal/` separate config (`config`), scope (`scope`), orchestration (`orchestrator`, `app`), execution (`runner`), storage (`storage`), reporting (`report`), auth (`auth`), and UI (`ui`, `tui`). Integrations with external tools live in `internal/modules/<tool>/` and implement the interface in `internal/modules/module.go`. Unit tests sit beside production files as `*_test.go`; parser fixtures belong in `testdata/`. Runtime scan output is written to `runs/` and is gitignored.

## Architecture (read `docs/ARCHITECTURE.md` for depth)

- Every scanner is a `modules.Module` (`internal/modules/module.go`) declaring `Name()`, `Description()`, `Requires()`, `Produces()`, and `Run(ctx, *RunContext, runner.Executor)`.
- `internal/orchestrator` builds a DAG from the modules selected by a profile, rejects duplicate producers/cycles/unresolvable deps at build time, then executes ready modules in waves (concurrent per wave, in profile-declared order for determinism). Upstream failure marks dependents `skipped` rather than aborting.
- New scanner integrations: add `internal/modules/<tool>/<tool>.go`, then wire it into `buildRegistry()` in `internal/app/app.go` (modules take `cfg.ToolPath("<tool>")`). Follow `internal/modules/dnsx/dnsx.go` as the pattern.
- Scope enforcement is the central security boundary. `internal/modules/context.go` `filterArtifact` is the single choke point: every line-oriented text artifact declared with `Scoped: true` (or named in the legacy `scopedTextArtifacts` allowlist: subdomains, resolved_hosts, alive_urls, crawled_urls, open_ports, historical_urls, attack_surface_urls) is filtered against the scope before any downstream module reads it; rejections land in `00_meta/scope-rejections.jsonl`. New modules producing host/URL/IP/host:port list artifacts must set `Artifact.Scoped: true` — do not rely on the allowlist alone. Raw tool outputs (JSONL/XML) and derived data (wordlists, paths, secrets) must NOT set `Scoped`. Never re-derive targets by parsing tool output directly.
- Modules must execute through the injected `runner.Executor` (never `os/exec` directly); `--dry-run` selects `NewDryRunExecutor`, which records commands without network access.
- `scanforge plan TARGET --preset deep` prints the validated waves without running anything — use it to sanity-check profiles before `run`.
- `scanforge.yaml` is user config (gitignored); `scope.txt` is an example scope file (also gitignored). Scope is mandatory, config is not. Runs land in `runs/<target>/<timestamp>/` (dirs `00_meta/`…`06_vulns/`, plus `report.json`/`report.md`).

## Build, Test, and Development Commands

- `make build` builds the binary with version ldflags (VERSION/COMMIT/DATE injected into `internal/version`).
- `make test`, `make race`, `make vet`, `make lint` and `make fmt` wrap the corresponding Go toolchain commands.
- `make lint` runs `golangci-lint`; `.golangci.yml` uses the v2 config format (`version: "2"`). CI pins golangci-lint v1.64.8, so a local install of v1.64+ or v2.x works.
- `go run ./cmd/scanforge --help` runs the CLI without creating a binary.
- CI (`.github/workflows/ci.yml`) runs `go vet ./...`, `go test -race ./...`, a coverage run, and `go build`; `make test` (`go test ./...`) is the fast local equivalent.
- `go test ./internal/orchestrator -run TestOrchestratorSuccess` runs one focused test.
- `go vet ./...` checks common Go correctness issues; `go fmt ./...` formats all Go packages before review.
- `docker compose run scanforge run example.com --profile web` exercises the containerized workflow. Only target hosts explicitly listed in the confirmed/mounted scope file.
- External tool versions are pinned in `.tools-version` (single source shared by `install.sh`, `install.ps1` and the `Dockerfile`); update it when bumping a tool.

Go 1.25.x is expected, as declared in `go.mod` and CI.

## Coding Style & Naming Conventions

Follow standard Go formatting and keep packages small and purpose-specific. Use tabs as produced by `gofmt`. Package names should be short and lowercase; exported identifiers use `PascalCase`, internal identifiers use `camelCase`, and filenames use lowercase words (for example, `commandlog.go`). Wrap errors with useful context using `%w`. UI output goes through the internal `ui`/`tui` packages (Bubble Tea); don't add another terminal library.

## Testing Guidelines

Use Go's standard `testing` package. Name tests `TestBehavior` and keep them close to the package they verify. Prefer table-driven cases for validation and parsing logic, and use fakes or dry-run executors instead of invoking real security tools. Add fixtures to `testdata/` when representative tool output is needed. No numeric coverage threshold is enforced, but changed behavior should include regression coverage.

## Documentation & Commit Guidelines

The README and `docs/*.md` are written in French first (mirrored under `docs/fr/` and `docs/zh/`); keep new docs consistent with that. Recent history favors concise, imperative Conventional Commit-style subjects (`feat:`, `fix:`, `test:`, `docs:`, or `chore:`) and each commit stays focused.

Pull requests should explain the user-visible change, list validation commands, and link related issues. Include terminal output or screenshots for CLI presentation changes. Call out new external-tool requirements (`.tools-version`), configuration changes, and any security or scope-validation impact.
