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
