# Architecture

## Artifact-driven pipeline

Each module declares the artifacts it requires and produces. ScanForge builds
a DAG, rejects duplicate producers, missing dependencies and cycles, then runs
the ready modules in waves.

Main chains:

```text
subfinder → subdomains → dnsx → resolved_hosts
resolved_hosts → httpx → alive_urls
resolved_hosts → naabu → open_ports → nmap
alive_urls → tlsx / whatweb / wafw00f / katana / ffuf / nuclei
target → gau → historical_urls
```

`scanforge plan TARGET --preset deep` displays the validated waves without
running any tool or creating a run.

## Security boundary

The effective scope is built in the application layer and passed to the
`RunContext`. Before publication, textual artifacts containing hosts, IPs,
ports or URLs are centrally filtered. A rejected value therefore never reaches
a downstream module and is recorded in the rejection log.

The `exact` mode always keeps the root target in the Subfinder output so that
DNSX and HTTPX can continue without implicitly widening the perimeter. Nmap
receives the validated host/port pairs produced by Naabu and runs scans
restricted to those ports.

## Output organization

A run is stored under `runs/<target>/<timestamp>/`:

```text
00_meta/       manifest, commands, stderr, scope and rejections
01_subdomains/ Subfinder and DNS results
02_http/       HTTP probes and TLS enrichments
03_ports/      Naabu results and Nmap XML
04_web/        technologies and WAF detection
05_content/    crawl, historical URLs and fuzzing
06_vulns/      Nuclei results
report.json    normalized report
report.md      readable summary
```

The manifest distinguishes the `completed`, `partial` and `failed` states,
references the produced artifacts and keeps the scope source for audit.

## Triage layer (H3.1)

`scanforge triage <run>` derives interpretation from the report without ever
modifying it:

```text
report.json ──► finding.FromReport ──► canonical findings (deterministic IDs)
                                          │
                                          ▼
                              finding.BuildRelations (L0/L1)
                                          │
                                          ▼
                              triage engine: group → bundle → analyze → validate
                                          │
                                          ▼
                          <run>/triage/ (manifest, relations, insights, report.md)
```

The boundary is strict: **ScanForge owns facts, AI owns interpretations,
validation sits between them.**

- `internal/finding` projects the report into flat findings with
  deterministic IDs (`F-` + hash of source|template|asset|matched_at|evidence)
  and computes deterministic relations (duplicate 1.00, shared CVE 0.99,
  same endpoint 0.95, same asset 0.80). L2 (semantic) relations can add to
  them but never override them.
- `internal/triage` runs the pipeline: grouping (union-find over the relation
  graph), deterministic insights (summary + duplicate groups), optional LLM
  analysis, validation and reconciliation (priority-ordered, stable IDs).
- The LLM receives only a reduced projection (`TriageBundle`): truncated
  evidence, no raw tool output, capped at 150 findings. Its output is
  validated against the facts — unknown finding IDs, CVEs or evidence strings
  reject the whole insight — so the model cannot inject new truths.
- `internal/inference` abstracts the transport behind a `Client` interface;
  the bundled implementation speaks the OpenAI-compatible chat completions
  API (llama.cpp, vLLM, Ollama, ...).
- Provenance is recorded in `triage/manifest.json` (model, prompt version,
  input digest, temperature) and the cache reuses results when the input
  digest, model and prompt version are unchanged (`--force` bypasses it).
