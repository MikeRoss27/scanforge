# Scope management

Scope is always mandatory as a safety guard, but the `scope.txt` file is not.
ScanForge resolves an effective perimeter before creating a run, then filters
the artifacts passed between modules.

## Implicit scope

Without an applicable file, the `exact` mode only allows the target:

```bash
scanforge plan example.com --scope-mode exact
```

The `domain` mode allows the root domain and its subdomains:

```bash
scanforge plan example.com --scope-mode domain
```

Add or exclude entries with repeatable options:

```bash
scanforge run example.com --scope-mode domain \
  --scope-add api.other.test \
  --scope-add 10.20.0.0/24 \
  --exclude admin.example.com \
  --exclude '*.legacy.example.com'
```

Exclusions take priority. CIDRs are only accepted as explicit additions; the
`domain` mode rejects IPs, CIDRs and single-label names.

## Scope file

A file accepts hosts, wildcards, CIDRs and exclusions prefixed with `!`:

```text
example.com
*.example.com
10.20.0.0/24
!admin.example.com
!*.legacy.example.com
```

Use it explicitly with `--scope scope-client.txt`, or configure
`default_scope`. A file provided via `--scope` is strict: if the target is not
allowed, the run fails without fallback. It cannot be combined with
`--scope-mode`, `--scope-add` or `--exclude`.

If the default configured file is missing or does not cover the target,
ScanForge proposes an implicit scope and asks for confirmation. A valid file
that covers the target does not require additional confirmation.

## Traceability and CI

Each run keeps:

- `00_meta/effective-scope.txt`: rules actually applied;
- `scope_source` and `scope_mode` in the manifest;
- `00_meta/scope-rejections.jsonl`: rejected values.

In CI, preview with `plan`, then pass `--confirm-scope` only for an implicit
scope. This option confirms the displayed perimeter; it never disables
filtering.
