# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.1] - 2026-07-04

### Added

- CLI orchestrator for authorized recon workflows
- Profiles `passive` (subfinder → httpx) and `web` (+ nuclei)
- Scope validation with exact hosts, wildcards, and CIDR support
- Dry-run mode with command logging and timestamped run directories
- Manifest generation for each scan run
- `scanforge init` to create `scanforge.yaml`, `scope.txt`, and workspace layout
- `scanforge doctor` to validate external tools, workspace, config, and scope
- `scanforge version` with build metadata support
- YAML configuration via `scanforge.yaml` (`--config` flag and `SCANFORGE_CONFIG`)
- Verbose output flag for runs and doctor checks
- Parser tests for httpx and nuclei normalized outputs
- Unit tests for scope, config, doctor, init, and dry-run app wiring
- GitHub Actions CI and release workflows with multi-platform binaries

[0.0.1]: https://github.com/MikeRoss27/scanforge/releases/tag/v0.0.1
