# Architecture

## Artifact-driven pipeline

Each module declares the artifacts it requires and produces. ScanForge builds
a DAG, rejects duplicate producers, missing dependencies and cycles, then
starts each module as soon as its required artifacts are available. A slow
independent module therefore does not hold back another ready branch.

Main chains:

```text
                         ┌→ dnsx (passive input) ───────────┐
subfinder → subdomains ──┤                                  ├→ resolved_hosts
                         └→ dnsbrute → dnsx (late results) ─┘
resolved_hosts → httpx → alive_urls
resolved_hosts → naabu → open_ports → nmap
alive_urls → tlsx / whatweb / wafw00f / katana / ffuf / nuclei
target → gau → historical_urls
crawled_urls/historical_urls/discovered_paths → jssecrets → js_secrets → dbdetect → db_fingerprint → dbenum
```

`ffuf`, `nuclei` and `katana` soft-depend on `wafw00f`'s `waf_raw` artifact
(`modules.SoftRequires`): they wait for wafw00f to finish when it is part of
the selected profile, but never error if it isn't. When wafw00f reports a WAF,
`RunContext.WAFInfo` carries that to the three scanners, which back off
automatically — lower concurrency/rate-limit, a randomized per-request delay,
and User-Agent rotation (`modules.RandomUserAgent`) — unless the operator
already set an explicit rate limit or a `User-Agent` header, which always
wins. `jssecrets` also soft-depends on `historical_urls` and
`discovered_paths` so it can scan JS URLs gau/ffuf found that the crawl missed
(`collectJSURLs`).

DNSX resolves passive discoveries while DNS bruteforce runs. Once the optional
producer finishes, DNSX resolves only its additional hosts, merges both JSONL
streams and publishes the final scoped artifact. A failed optional producer
wakes the waiter so the passive branch can still continue.

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

## Console output

Scans render as a chronological, tagged event stream, not a fullscreen
interface: the terminal keeps its scrollback, everything stays copy/paste
and grep/tee friendly, and CI loses nothing. Modules never print styled
output — they emit semantic events (`ModuleStart`, `ModuleDone`,
`Finding`, `Warning`, `ModuleProgress`) onto the orchestrator's channel,
and `internal/console` decides how those look:

- phases are derived from each batch the scheduler dispatches
  (`DISCOVERY`, `RESOLUTION`, `PORTS`, `WEB SURFACE`, `VULNERABILITY ANALYSIS`)
  and printed as one-line separators; a batch that mixes independent phases
  lists them (`PORTS · WEB SURFACE`), and no phase is shown when the batch
  only contains unknown modules. Verbose wave numbers refer to the static DAG
  plan and do not act as runtime barriers
- module lifecycle lines carry `[RUN]` / `[OK]` / `[ERR]` / `[SKP]` / `[WRN]`
  tags, dim timestamps (`HH:MM:SS`) and adaptive columns
- medium/low/info findings render compactly with their actual evidence
  (exposed email, secret, internal host, version); identical values are
  counted but printed once, and a per-type cap stops a leaky page from
  flooding the scrollback
- critical/high findings expand into a structured block
  (Target / Module / Severity / Evidence) once per finding type; suppressed
  occurrences are counted and listed in the closing summary's
  `Finding types` recap (e.g. `INFO Email address exposed (jssecrets) ×9`),
  grouped from the final `report.json` (source/title/severity) so its counts
  always agree with the severity totals shown above it, instead of the
  live event stream, which can lag or double-count
- a compact volatile loading block is drawn only on interactive terminals
  (never on pipes, CI runners or in quiet mode). A canonical hammer and anvil come from an
  embedded imagegen sprite sheet. Forty poses are sampled once along a rigid
  pivot rotation into a 16-column, 6-row terminal image. The 25 Hz cycle uses
  anticipation, an accelerated downswing, recoil and an eased return; it lasts
  1.6 seconds. Each redraw uses one terminal write to reduce flicker. Steel, wood and embers have truecolor / ANSI-256 palettes;
  monochrome terminals retain the silhouette. Status and real module counters
  appear alongside the sprite; below 50 columns a single-line spinner is used.
  The stationary anvil is shared across poses to avoid wobble. Before each
  event the entire block is cleared, preserving scrollback. The large smith
  stays in the startup banner (`SCANFORGE_SPINNER=forge|dots|off`).
- verbosity is structured: `-v` adds wave numbers, `-vv` echoes the commands
  executed by external tools, `-vvv` adds their stdout/stderr redirection
  details; `-q` keeps findings, warnings, errors and the final summary only
- the terminal width rules everything: rules, separators and event lines
  wrap or shorten accordingly (verified from 40 to 160 columns)

Dry-run commands are printed through the renderer as an unframed,
unwrapped transcript (so they stay copy/pasteable) and phase separators wait
for the first visible line of their wave — a wave with no output never leaves
a dangling header. Module failures are rendered only by the console: the
orchestrator no longer writes raw `ERROR:` lines to stderr alongside the
structured `[ERR]` block.

The interactive prompts (scope confirmation, setup wizard) write to stderr
instead of stdout; everything else goes through the renderer.

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
`partial` means the module ran but was degraded rather than clean: `httpcheck`
and `jssecrets` report it when every URL they tried to fetch was unreachable,
and `jsverify` reports it when no browser was available, the browser failed
to launch, or every PoC replay came back `unreachable` — so a WAF or network
issue blocking every request shows up as a visible degradation instead of a
false-clean `completed` with zero findings.

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

## Persistance, reprise et accès agents

- **Persistance par fichiers** : le manifest (`00_meta/manifest.json`) est aussi le store de checkpoints (statut + `input_hash` par module, écriture atomique). Pas de base SQLite : les runs restent lisibles, copiables et versionnables. Voir `docs/RESUME.md`.
- **Historique d'assets** (`internal/assets`) : `runs/<cible>/assets.jsonl`, append-only, écrit atomiquement en fin de run complet à partir du rapport consolidé (`internal/report`). `--incremental` installe un `modules.InputFocus` sur le `RunContext` ; nuclei, ffuf, katana et jssecrets lisent leur entrée via `RunContext.FocusedInput`, qui ne fait que retirer des lignes d'un artefact déjà filtré par le scope. Le digest du focus entre dans le hash d'entrée des checkpoints (`internal/orchestrator/checkpoint.go`). Voir `docs/INCREMENTAL.md`.
- **Scheduler** (`internal/scheduler`) : décorateur d'`Executor` (concurrence, req/s, budget de commandes, timeouts).
- **Événements** (`internal/events`) : bus typé en complément du DAG, scope vérifié en premier, `00_meta/events.jsonl`.
- **Workflows** (`internal/workflows`) : compilés vers la sélection de modules d'un profil ; le DAG et le filtrage de scope restent inchangés.
- **Vulnintel** (`internal/vulnintel`) : cache NVD/KEV/EPSS, mis à jour uniquement par `scanforge intel update`.
- **MCP / API** : lecture des runs, scans actifs désactivés par défaut (`--allow-active` + fichier de scope strict, journal d'audit).
- **Secrets** : les secrets trouvés sur la cible restent en clair dans les findings (preuves) ; seuls les identifiants de l'opérateur sont masqués.
