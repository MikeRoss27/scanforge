# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `scanforge resume <run-id>`, `scanforge status <run-id>` and `scanforge runs list`: file-based checkpoints in the existing manifest (per-module status, input hash, atomic writes). Resume skips completed modules whose inputs (scope, params, tool version, required artifacts) are unchanged and never widens the scope (see `docs/RESUME.md`)
- Global scheduler (`internal/scheduler`): concurrency, requests-per-second, command budget and timeout caps via a `limits:` config section and `--concurrency/--rps/--max-requests/--command-timeout`; counts launched commands, not HTTP requests
- Typed discovery event bus (`internal/events`) with deterministic IDs, dedup, depth/budget limits and mandatory scope gating, persisted to `00_meta/events.jsonl`; demo wiring behind the off-by-default `--events` flag
- YAML workflows (`--workflow file.yaml`, `scanforge workflow validate`, `plan --workflow`): validated against the module registry, no shell steps, compiled to the existing DAG (see `docs/WORKFLOWS.md`)
- Local vulnerability intel (`scanforge intel update|status`): NVD, CISA KEV and EPSS cached as files with provenance; `techcve` uses it when present and labels matches `exact-cpe-range` / `version-range` / `name-only` (name-only is never confirmed)
- `scanforge mcp` (stdio) and `scanforge api` (loopback HTTP): read-only access to runs, assets, findings and evidence; active scan tools are disabled unless `--allow-active` is given together with a strict `--scope` file, and every active call is audit-logged (see `docs/MCP.md`, `docs/API.md`)

### Changed

- Go toolchain bumped to 1.27 (`go.mod`, CI, release workflow); CI lint pinned to golangci-lint v2.15.0
- Go modules updated (chromedp v0.24, cdproto v0.160.8, goja, ws); `jsverify` ported to chromedp's generic API
- Pinned external tools bumped: subfinder v2.17.0, dnsx v1.3.1, httpx v1.12.0, naabu v2.7.0, katana v1.8.0, nuclei v3.11.1, tlsx v1.5.0, ffuf v2.3.0 (SecLists, gau, shuffledns, massdns, wafw00f unchanged)
- Fixed existing golangci-lint findings (unchecked errors, unused types)

### Notes

- Findings keep leaked secret values in full (they are bounty evidence); only the operator's own credentials are masked in API/MCP output

## [0.10.0] - 2026-11-23

### Added

- WAF-aware scanning: `ffuf`, `nuclei` and `katana` soft-depend on `wafw00f` and automatically back off (lower concurrency/rate-limit, randomized request delay, User-Agent rotation) when a WAF is detected, unless an explicit rate limit or `User-Agent` header was already set
- New `dbdetect` module: passively fingerprints Supabase/Firebase/Appwrite/PocketBase backends from already-crawled pages/JS and auto-scopes the discovered backend host
- New `dbenum` module: bounded, read-only enumeration of a `dbdetect`-discovered backend (table/collection listing, row counts, permission checks); never reads row/document contents
- `jssecrets` now also scans JS-looking URLs surfaced by `gau`'s historical URLs and `ffuf`'s fuzzed paths, not just the crawl
- `jssecrets` secret patterns: AWS session tokens, additional AWS access-key-ID prefixes (`ASIA`/`ABIA`/`ACCA`), Cloudinary URLs, Postman API keys, Basic-Auth headers, and dedicated, verified formats for Anthropic, OpenAI (current + legacy), xAI, Groq, OpenRouter and Perplexity API keys
- `scanforge benchmark` command: runs the real scan pipeline against bundled intentionally-vulnerable lab targets (Firing Range, testphp.vulnweb.com, Juice Shop demo, local DVWA) and scores detection against documented expectations (maintainer/CI tool)

### Fixed

- `jssecrets`'s `openai-api-key` pattern used the wrong separator and matched Anthropic's `sk-ant-` prefix, so it never caught real OpenAI project/service-account keys and misreported Anthropic keys as OpenAI's
- `httpcheck`, `jssecrets` and `jsverify` now report status `partial` (with a reason) instead of a false-clean `completed` when every request/replay they attempted was unreachable
- The closing summary's `Finding types` recap is now derived from the final `report.json`, so its counts always match the severity totals shown above it instead of occasionally disagreeing with the live event stream

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
