// Package techcve correlates technologies fingerprinted by httpx and whatweb
// with a bundled dataset of version-specific CVEs, so known-vulnerable
// software versions are flagged even when no nuclei template covers them.
package techcve

import (
	"bufio"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
	"gopkg.in/yaml.v3"
)

//go:embed cves.yaml
var datasetYAML []byte

const outputRel = "06_vulns/cve-findings.jsonl"

// cveEntry is one row of the embedded version-based CVE dataset.
type cveEntry struct {
	ID             string  `yaml:"id"`
	Tech           string  `yaml:"tech"`
	Title          string  `yaml:"title"`
	Severity       string  `yaml:"severity"`
	CVSS           float64 `yaml:"cvss"`
	MinVersion     string  `yaml:"min-version"`
	MaxVersion     string  `yaml:"max-version"`
	Reference      string  `yaml:"reference"`
	Note           string  `yaml:"note"`
	EPSS           float64 `yaml:"epss"`
	EPSSPercentile float64 `yaml:"epss-percentile"`
	KEV            bool    `yaml:"kev"`
}

// finding is one emitted record per affected host+technology pair.
type finding struct {
	Host           string  `json:"host"`
	Tech           string  `json:"tech"`
	Version        string  `json:"version"`
	CVEID          string  `json:"cve_id"`
	Title          string  `json:"title"`
	Severity       string  `json:"severity"`
	CVSS           float64 `json:"cvss,omitempty"`
	Reference      string  `json:"reference"`
	Note           string  `json:"note,omitempty"`
	EPSS           float64 `json:"epss,omitempty"`
	EPSSPercentile float64 `json:"epss_percentile,omitempty"`
	KEV            bool    `json:"kev,omitempty"`
}

type techHit struct {
	host    string
	tech    string
	version string
}

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Name() string { return "techcve" }
func (m *Module) Description() string {
	return "Correlates detected technologies and versions with known CVEs from a bundled dataset"
}
func (m *Module) Requires() []string { return []string{"httpx_raw"} }
func (m *Module) Produces() []string { return []string{"cve_findings"} }

func (m *Module) Run(ctx context.Context, runCtx *modules.RunContext, _ runner.Executor) (*modules.Result, error) {
	entries, err := loadDataset()
	if err != nil {
		return nil, err
	}

	var hits []techHit

	httpArt, err := runCtx.MustArtifact("httpx_raw")
	if err != nil {
		return nil, err
	}
	fromHttpx, err := collectHttpx(runCtx.Run.Path(httpArt.Path))
	if err != nil {
		return nil, fmt.Errorf("failed to parse httpx output: %w", err)
	}
	hits = append(hits, fromHttpx...)

	if art, ok := runCtx.GetArtifact("whatweb_raw"); ok {
		fromWhatWeb, err := collectWhatWeb(runCtx.Run.Path(art.Path))
		if err != nil {
			return nil, fmt.Errorf("failed to parse whatweb output: %w", err)
		}
		hits = append(hits, fromWhatWeb...)
	}

	var findings []finding
	dedup := make(map[string]struct{})
	for _, hit := range hits {
		for _, entry := range entries {
			if entry.Tech != normalizeTech(hit.tech) {
				continue
			}
			if !versionAffected(hit.version, entry.MinVersion, entry.MaxVersion) {
				continue
			}
			key := hit.host + "|" + entry.ID + "|" + hit.tech
			if _, ok := dedup[key]; ok {
				continue
			}
			dedup[key] = struct{}{}
			findings = append(findings, finding{
				Host:           hit.host,
				Tech:           hit.tech,
				Version:        hit.version,
				CVEID:          entry.ID,
				Title:          entry.Title,
				Severity:       entry.Severity,
				CVSS:           entry.CVSS,
				Reference:      entry.Reference,
				Note:           entry.Note,
				EPSS:           entry.EPSS,
				EPSSPercentile: entry.EPSSPercentile,
				KEV:            entry.KEV,
			})
		}
	}

	if err := runner.AppendCommandLog(runCtx.Run.CommandsLog, runner.Command{
		Name: "techcve (native)",
		Args: []string{
			"-input", runCtx.Run.Path(httpArt.Path),
			"-entries", strconv.Itoa(len(entries)),
		},
	}); err != nil {
		return nil, fmt.Errorf("failed to write commands log: %w", err)
	}

	if err := writeFindings(runCtx.Run.Path(outputRel), findings); err != nil {
		return nil, err
	}

	if err := runCtx.AddArtifact("cve_findings", modules.Artifact{
		Name: "cve_findings",
		Type: "jsonl",
		Path: outputRel,
	}); err != nil {
		return nil, fmt.Errorf("failed to publish CVE findings: %w", err)
	}

	return &modules.Result{
		Name:   m.Name(),
		Status: "completed",
		OutputFiles: map[string]string{
			"cve_findings": outputRel,
		},
	}, nil
}

func loadDataset() ([]cveEntry, error) {
	var entries []cveEntry
	if err := yaml.Unmarshal(datasetYAML, &entries); err != nil {
		return nil, fmt.Errorf("failed to parse embedded CVE dataset: %w", err)
	}
	return entries, nil
}

// collectHttpx parses httpx JSONL lines and returns host + tech/version pairs.
func collectHttpx(path string) ([]techHit, error) {
	var hits []techHit
	err := scanJSONLines(path, func(line []byte) {
		var record struct {
			Host string   `json:"host"`
			URL  string   `json:"url"`
			Tech []string `json:"tech"`
		}
		if json.Unmarshal(line, &record) != nil {
			return
		}
		host := normalizeHost(record.Host)
		if host == "" {
			host = normalizeHost(record.URL)
		}
		if host == "" {
			return
		}
		for _, tech := range record.Tech {
			name, version := splitTechVersion(tech)
			hits = append(hits, techHit{host: host, tech: name, version: version})
		}
	})
	if err != nil {
		return nil, err
	}
	return hits, nil
}

// collectWhatWeb parses whatweb text output such as
// "http://example.com WordPress[6.3] ApacheTomcat[9.0.79]".
func collectWhatWeb(path string) ([]techHit, error) {
	var hits []techHit
	err := scanTextLines(path, func(line string) {
		rawURL := urlPattern.FindString(line)
		host := normalizeHost(rawURL)
		if host == "" {
			return
		}
		for _, field := range strings.Fields(line) {
			open := strings.IndexByte(field, '[')
			if open <= 0 {
				continue
			}
			name := strings.Trim(field[:open], " ,")
			if name == "" {
				continue
			}
			value := ""
			if close := strings.IndexByte(field[open+1:], ']'); close >= 0 {
				value = field[open+1 : open+1+close]
			}
			version := ""
			if isVersionLike(value) {
				version = value
			} else if parts := strings.Fields(value); len(parts) > 0 && isVersionLike(parts[len(parts)-1]) {
				version = parts[len(parts)-1]
			}
			hits = append(hits, techHit{host: host, tech: name, version: version})
		}
	})
	if err != nil {
		return nil, err
	}
	return hits, nil
}

var urlPattern = regexp.MustCompile(`https?://[^\s]+`)

// splitTechVersion splits "WordPress:6.3.1" (httpx) or "Apache Tomcat 9.0.79"
// (whatweb) into a tech name and an optional version.
func splitTechVersion(raw string) (name, version string) {
	value := strings.TrimSpace(raw)
	if i := strings.IndexByte(value, ':'); i > 0 {
		return strings.TrimSpace(value[:i]), strings.TrimSpace(value[i+1:])
	}
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return value, ""
	}
	for i := len(fields) - 1; i > 0; i-- {
		if isVersionLike(fields[i]) {
			return strings.Join(fields[:i], " "), fields[i]
		}
	}
	return value, ""
}

func isVersionLike(value string) bool {
	if value == "" || !isdigit(value[0]) {
		return false
	}
	prefix := value
	if i := strings.IndexAny(prefix, " \t"); i >= 0 {
		prefix = prefix[:i]
	}
	for _, r := range prefix {
		if !isdigit(byte(r)) && r != '.' {
			return false
		}
	}
	return true
}

func isdigit(b byte) bool { return b >= '0' && b <= '9' }

// normalizeTech lowercases, collapses spaces and applies aliases so the
// fingerprint ("Apache Tomcat", "jQuery UI") maps onto dataset keys.
func normalizeTech(name string) string {
	value := strings.ToLower(strings.TrimSpace(name))
	value = strings.Join(strings.Fields(value), "-")
	switch value {
	case "apache-tomcat", "apachetomcat", "tomcat":
		return "tomcat"
	case "apache":
		return "apache"
	case "jquery-ui", "jqueryui":
		return "jquery-ui"
	}
	return value
}

// versionAffected reports whether version falls in [min, max).
func versionAffected(version, min, max string) bool {
	if version == "" {
		return false
	}
	if min != "" && compareVersions(version, min) < 0 {
		return false
	}
	if max != "" && compareVersions(version, max) >= 0 {
		return false
	}
	return true
}

// compareVersions compares dotted numeric versions ("3.5.0", "10.1.18").
// Non-numeric segments compare as 0.
func compareVersions(a, b string) int {
	as, bs := splitNumeric(a), splitNumeric(b)
	for i := 0; i < len(as) || i < len(bs); i++ {
		var av, bv int
		if i < len(as) {
			av = as[i]
		}
		if i < len(bs) {
			bv = bs[i]
		}
		if av < bv {
			return -1
		}
		if av > bv {
			return 1
		}
	}
	return 0
}

func splitNumeric(value string) []int {
	value = strings.TrimPrefix(value, "v")
	value = strings.TrimPrefix(value, "V")
	var parts []int
	for _, part := range strings.FieldsFunc(value, func(r rune) bool {
		return !isdigit(byte(r))
	}) {
		if n, err := strconv.Atoi(part); err == nil {
			parts = append(parts, n)
		}
	}
	return parts
}

func normalizeHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
		return strings.ToLower(u.Hostname())
	}
	return strings.ToLower(raw)
}

func writeFindings(path string, findings []finding) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("failed to create CVE findings directory: %w", err)
	}
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create CVE findings file: %w", err)
	}
	defer func() { _ = file.Close() }()

	encoder := json.NewEncoder(file)
	for _, item := range findings {
		if err := encoder.Encode(item); err != nil {
			return fmt.Errorf("failed to write CVE findings: %w", err)
		}
	}
	return nil
}

func scanJSONLines(path string, consume func([]byte)) error {
	return scanTextLines(path, func(line string) { consume([]byte(line)) })
}

func scanTextLines(path string, consume func(string)) error {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			consume(line)
		}
	}
	return scanner.Err()
}
