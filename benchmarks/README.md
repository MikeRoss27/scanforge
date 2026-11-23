# ScanForge benchmarks

`scanforge benchmark` is a maintainer tool, not part of an authorized client
engagement. It runs the real scan pipeline against known, intentionally
vulnerable lab targets and scores the result against documented
expectations, so a regression in the pipeline or in detection shows up as a
failing benchmark instead of shipping silently. It's built to be run by a
human contributor and equally by an AI agent (Claude Code or otherwise)
sanity-checking a change.

```
scanforge benchmark list                     # see the bundled labs
scanforge benchmark run firing-range         # run one lab, human output
scanforge benchmark run testphp-vulnweb --json
scanforge benchmark run dvwa --target http://localhost:4280
scanforge benchmark run --all                # run every lab, sequentially
```

The corpus lives in `internal/benchmark/corpus/*.yaml` and is embedded into
the binary (`go:embed`), so the command works from anywhere, not just a repo
checkout.

## The bundled labs

| Lab | Target | Mode | Why |
|---|---|---|---|
| `firing-range` | `public-firing-range.appspot.com` | advisory | Google's own scanner-test app. Built and run by Google specifically for this — safe to hit directly, any volume. |
| `testphp-vulnweb` | `testphp.vulnweb.com` | advisory | Acunetix's long-standing public scanner-test target. Also explicitly published for this — safe to hit directly. |
| `juice-shop-demo` | `demo.owasp-juice.shop` | advisory | OWASP Juice Shop's **shared public demo** — other people are practicing attacks on it too. Be considerate of load; this lab deliberately uses the lighter `vuln` profile (no ffuf/naabu/nmap). |
| `dvwa` | `localhost:4280` (you provide it) | strict | Damn Vulnerable Web Application, self-hosted via Docker. The only lab with a precisely, officially documented vulnerability set — the only one whose category expectations actually gate pass/fail. |

**Advisory vs. strict** — `firing-range`, `testphp-vulnweb` and
`juice-shop-demo` only fail the benchmark if the pipeline itself fails or
crashes (`Completed`); their "expected categories" (XSS, SQLi, …) are
computed and reported but never gate `overall_pass`, because their exact
current vulnerable content is only documented in unverified third-party
write-ups and can drift without that being a ScanForge regression. `dvwa`
is `strict`: pinned to a known Docker image with an officially documented
vulnerability list, so a missing category there is a real signal.

## Running DVWA locally

DVWA has no public demo (exposing one would be reckless), so it's always
self-hosted:

```sh
docker run --rm -d -p 4280:80 --name dvwa vulnerables/web-dvwa
```

Then open `http://localhost:4280`, log in with `admin` / `password`, click
**Create / Reset Database**, and set **DVWA Security** to `low` under
**DVWA Security** before running the benchmark. `scanforge benchmark run
dvwa` checks reachability first and prints these same instructions if the
container isn't up yet, instead of burning the timeout on a closed port.

## A reproducible, non-shared Juice Shop

Rather than load the shared public demo repeatedly, self-host it:

```sh
docker run --rm -p 3000:3000 bkimminich/juice-shop
scanforge benchmark run juice-shop-demo --target http://localhost:3000
```

## For an AI agent

`--json` gives a stable contract (field names are part of it, don't rely on
anything else): `scanforge benchmark run --all --json` emits a JSON array of

```json
{
  "lab": "firing-range",
  "target": "https://public-firing-range.appspot.com",
  "run_dir": "runs/public-firing-range.appspot.com/2026-11-22_01-00-00",
  "duration_seconds": 123.4,
  "completed": true,
  "overall_pass": true,
  "strict": false,
  "findings_total": 7,
  "categories": [{"name": "xss", "min_count": 1, "found": 7, "pass": true}],
  "technologies": [{"want": "nginx", "found": true}],
  "error": ""
}
```

A single-lab run (`scanforge benchmark run <lab> --json`) emits one such
object, not a one-element array. The process exit code is `0` only when
every requested lab's `overall_pass` is `true`; check that (or just the
exit code) rather than re-deriving pass/fail from the fields yourself.
`scanforge benchmark run <lab> --dry-run` sanity-checks the wiring (profile,
scope, module plan) with zero network I/O — use it to verify a code change
didn't break the pipeline shape itself before spending the time on a real
run.
