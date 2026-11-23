package orchestrator

import (
	"bufio"
	"encoding/json"
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

// artifactSummarizers override the default line count for artifacts whose
// line count is meaningless: JSON documents (one line, many results) or
// tool transcripts (banners, progress chatter).
var artifactSummarizers = map[string]func(path string) string{
	"discovered_paths": summarizeFfufJSON,
	"waf_raw":          summarizeWafw00f,
	"nuclei_raw":       summarizeNucleiJSONL,
}

func summarizeArtifact(runCtx *modules.RunContext, art modules.Artifact) string {
	if summarize, ok := artifactSummarizers[art.Name]; ok {
		return summarize(runCtx.Run.Path(art.Path))
	}
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

// summarizeFfufJSON counts the entries of ffuf's {"results": [...]} JSON
// document. An unreadable or differently shaped file yields no summary
// rather than a misleading count.
func summarizeFfufJSON(path string) string {
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer func() { _ = file.Close() }()
	var doc struct {
		Results []json.RawMessage `json:"results"`
	}
	if err := json.NewDecoder(file).Decode(&doc); err != nil || len(doc.Results) == 0 {
		return ""
	}
	return countNoun(len(doc.Results), "path")
}

// summarizeWafw00f reads wafw00f's text transcript (ASCII banner included)
// and reports how many of the checked hosts sit behind a WAF, instead of
// counting banner lines.
func summarizeWafw00f(path string) string {
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer func() { _ = file.Close() }()

	checked, protected := 0, 0
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.Contains(line, "Checking http"):
			checked++
		case strings.Contains(line, " is behind ") || strings.Contains(line, " seems to be behind "):
			protected++
		}
	}
	if scanner.Err() != nil || checked == 0 {
		return ""
	}
	if protected > checked {
		protected = checked
	}
	if protected == 0 {
		return "no WAF on " + countNoun(checked, "host")
	}
	return fmt.Sprintf("%d/%s behind a WAF", protected, countNoun(checked, "host"))
}

// summarizeNucleiJSONL counts genuine matches in nuclei's JSONL output. The
// module always passes -matcher-status, which makes nuclei write one line
// per template *attempted* against each URL - including failed matches and
// request errors - not one line per match. Counting raw lines as "findings"
// wildly overstates the result (a WAF catch-all page alone can produce
// hundreds of same-looking non-matches); only matcher-status:true lines (or
// an absent field, for older nuclei output written without the flag) are
// real matches.
func summarizeNucleiJSONL(path string) string {
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer func() { _ = file.Close() }()

	matches := 0
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var record struct {
			MatcherStatus *bool `json:"matcher-status"`
		}
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			continue
		}
		if record.MatcherStatus == nil || *record.MatcherStatus {
			matches++
		}
	}
	if scanner.Err() != nil || matches == 0 {
		return ""
	}
	return countNoun(matches, "finding")
}

func countNoun(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
