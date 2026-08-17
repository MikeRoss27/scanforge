package orchestrator

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/MikeRoss27/scanforge/internal/modules"
)

// artifactLabels maps produced artifact names to the noun used in the
// per-module completion line, e.g. "8 subdomains" or "23 alive hosts".
var artifactLabels = map[string]string{
	"subdomains":       "subdomains",
	"resolved_hosts":   "hosts",
	"alive_urls":       "alive hosts",
	"httpx_raw":        "probed hosts",
	"open_ports":       "open ports",
	"crawled_urls":     "URLs",
	"historical_urls":  "URLs",
	"discovered_paths": "paths",
	"js_secrets":       "secrets",
	"js_payloads":      "payloads",
	"js_verified":      "replayed",
	"tls_raw":          "certificates",
	"nuclei_raw":       "findings",
}

// moduleSummary derives a human-readable result count for a completed module
// from the first text artifact it produced (e.g. "8 subdomains"). It returns
// an empty string when there is nothing to count or the module produced no
// meaningful output, in which case the caller renders the plain status line.
func moduleSummary(runCtx *modules.RunContext, module modules.Module, result *modules.Result) string {
	if runCtx.DryRun || result == nil || result.Status != "completed" {
		return ""
	}

	var fallback modules.Artifact
	for _, produced := range module.Produces() {
		art, ok := runCtx.GetArtifact(produced)
		if !ok {
			continue
		}
		if art.Type != "text" {
			if fallback.Name == "" {
				fallback = art
			}
			continue
		}
		if label := summarizeArtifact(runCtx, art); label != "" {
			return label
		}
	}
	if fallback.Name != "" {
		return summarizeArtifact(runCtx, fallback)
	}
	return ""
}

func summarizeArtifact(runCtx *modules.RunContext, art modules.Artifact) string {
	count, err := countLines(runCtx.Run.Path(art.Path))
	if err != nil || count == 0 {
		return ""
	}
	label := artifactLabels[art.Name]
	if label == "" {
		return fmt.Sprintf("%d results", count)
	}
	return fmt.Sprintf("%d %s", count, label)
}

func countLines(path string) (int, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer func() { _ = file.Close() }()

	count := 0
	scanner := bufio.NewScanner(file)
	// Same 1MB ceiling as the scope filter and artifact consumers: a long
	// URL line must not wipe out the module's result summary.
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) != "" {
			count++
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return count, nil
}
