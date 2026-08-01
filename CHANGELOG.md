# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-08-02

### Added

- Optional implicit scope generation with `exact` and `domain` modes
- Repeatable `--scope-add` and `--exclude` rules
- `scanforge plan` for read-only scope and DAG inspection
- `safe`, `recon`, `vuln`, and `deep` presets
- `gau` and `tlsx` modules
- Effective-scope archive and JSONL rejection journal
- Dedicated usage, scope, and architecture documentation
- `--proxy` support (httpx, nuclei, katana, ffuf, whatweb, wafw00f, subfinder, gau, jssecrets) to route scan traffic through an intercepting proxy such as Caido or Burp Suite
- Repeatable `-H/--header` flag for authenticated scanning (session cookies, bearer tokens)
- Nuclei tuning flags: `--nuclei-severity`, `--nuclei-exclude-severity`, `--nuclei-tags`, `--nuclei-exclude-tags`, `--nuclei-rate-limit`, `--nuclei-templates`, `--nuclei-update-templates`
- `--nmap-concurrency` flag; nmap now runs a bounded worker pool instead of scanning hosts sequentially
- New native `jssecrets` module: scans crawled JavaScript for exposed secrets (AWS/GCP/Azure keys, DB connection strings, tokens, private keys, and more), public cloud storage buckets, internal hosts/IPs, email addresses, sensitive API endpoints, and reachable source maps
- Live per-module progress during `scanforge run` — a spinner per running module on interactive terminals, plain progress lines otherwise — shown by default without requiring `--verbose`
- `scanforge plan` and `scanforge doctor` now render color-coded tables instead of hand-aligned text
- Boxed scan summary panel at the end of every run (status, duration, module success/failure, findings by severity, output path)

### Changed

- Scope confirmation is required only when authorization is inferred
- Artifact filtering is enforced centrally before downstream consumption
- Nmap consumes Naabu's host/port results and restricts scans accordingly
- Reports include richer DNS, HTTP, port, TLS, and historical URL data
- `scanforge doctor` shows only the relevant version line instead of a tool's full ASCII banner

### Fixed

- DAG validation for missing producers, duplicate producers, and cycles
- Root target continuity in exact scope mode
- Run status propagation for partial and failed module executions
- Several modules (naabu, katana, wafw00f, whatweb, ffuf, nuclei, nmap) silently ignored artifact-publish errors, which could mask scope-filtering failures; every module now checks and propagates that error

[0.1.0]: https://github.com/MikeRoss27/scanforge/releases/tag/v0.1.0

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
