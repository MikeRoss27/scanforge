# Repository Guidelines

## Project Structure & Module Organization

ScanForge is a Go CLI. The executable entry point is `cmd/scanforge/main.go`, while command definitions live in `internal/cli/`. Core packages under `internal/` separate configuration, scope validation, orchestration, command execution, storage, reporting, and authentication. Integrations with external reconnaissance tools belong in `internal/modules/<tool>/` and implement the interface in `internal/modules/module.go`. Unit tests sit beside production files as `*_test.go`; reusable parser fixtures belong in `testdata/`. Static README media is stored in `public/`. Runtime scan output is written to `runs/` and should not be committed.

## Build, Test, and Development Commands

- `go build -o scanforge ./cmd/scanforge` builds the local CLI binary.
- `go run ./cmd/scanforge --help` runs the CLI without creating a binary.
- `go test ./...` runs the full test suite; this is the same test command used by CI.
- `go test ./internal/orchestrator -run TestOrchestratorSuccess` runs one focused test.
- `go vet ./...` checks common Go correctness issues.
- `go fmt ./...` formats all Go packages before review.
- `docker compose run scanforge run example.com --profile web` exercises the containerized workflow. Use only targets explicitly listed in the mounted scope file.

Go 1.25.x is expected, as declared in `go.mod` and CI.

## Coding Style & Naming Conventions

Follow standard Go formatting and keep packages small and purpose-specific. Use tabs as produced by `gofmt`. Package names should be short and lowercase; exported identifiers use `PascalCase`, internal identifiers use `camelCase`, and filenames use lowercase words (for example, `commandlog.go`). Wrap errors with useful context using `%w`. New scanner integrations should satisfy `modules.Module` and declare their required and produced artifacts.

## Testing Guidelines

Use Go's standard `testing` package. Name tests `TestBehavior` and keep them close to the package they verify. Prefer table-driven cases for validation and parsing logic, and use fakes or dry-run executors instead of invoking real security tools. Add fixtures to `testdata/` when representative tool output is needed. No numeric coverage threshold is enforced, but changed behavior should include regression coverage.

## Commit & Pull Request Guidelines

Recent history favors concise, imperative Conventional Commit-style subjects such as `feat: implement ...` and `docs: update ...`. Use an appropriate prefix (`feat:`, `fix:`, `test:`, `docs:`, or `chore:`) and keep each commit focused.

Pull requests should explain the user-visible change, list validation commands, and link related issues. Include terminal output or screenshots for CLI presentation changes. Call out new external-tool requirements, configuration changes, and any security or scope-validation impact.
