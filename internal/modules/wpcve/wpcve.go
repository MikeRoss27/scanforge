// Package wpcve correlates detected WordPress core/plugin/theme versions
// with the bundled advisory dataset (same model as techcve, keyed by WP
// slugs). Findings are emitted in the same schema as techcve so report
// generation, diff and export handle them like any other CVE finding.
package wpcve

import (
	"bufio"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/modules/wpcore"
	"github.com/MikeRoss27/scanforge/internal/runner"
	"gopkg.in/yaml.v3"
)

//go:embed cves_wp.yaml
var datasetYAML []byte

const outputRel = "06_vulns/wp-cve-findings.jsonl"

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Name() string { return "wpcve" }
func (m *Module) Description() string {
	return "Correlates WordPress core/plugin/theme versions with the bundled advisory dataset (embedded, offline)"
}
func (m *Module) Requires() []string     { return []string{"wp_fingerprint"} }
func (m *Module) SoftRequires() []string { return []string{"wp_plugins", "wp_themes"} }
func (m *Module) Produces() []string     { return []string{"wp_cve_findings"} }

type cveEntry struct {
	ID         string  `yaml:"id"`
	Tech       string  `yaml:"tech"`
	Title      string  `yaml:"title"`
	Severity   string  `yaml:"severity"`
	CVSS       float64 `yaml:"cvss"`
	MinVersion string  `yaml:"min-version"`
	MaxVersion string  `yaml:"max-version"`
	Reference  string  `yaml:"reference"`
	Note       string  `yaml:"note"`
}

type finding struct {
	Host      string  `json:"host"`
	Tech      string  `json:"tech"`
	Version   string  `json:"version"`
	CVEID     string  `json:"cve_id"`
	Title     string  `json:"title"`
	Severity  string  `json:"severity"`
	CVSS      float64 `json:"cvss,omitempty"`
	Reference string  `json:"reference"`
	Note      string  `json:"note,omitempty"`
}

func (m *Module) Run(ctx context.Context, runCtx *modules.RunContext, _ runner.Executor) (*modules.Result, error) {
	entries, err := loadDataset()
	if err != nil {
		return nil, err
	}

	fpArt, err := runCtx.MustArtifact("wp_fingerprint")
	if err != nil {
		return nil, err
	}
	fingerprints, err := wpcore.LoadFingerprint(runCtx.Run.Path(fpArt.Path))
	if err != nil {
		return nil, fmt.Errorf("failed to read wp_fingerprint: %w", err)
	}

	var findings []finding
	tracked := 0
	for _, host := range fingerprints {
		if host.CoreVersion == "" {
			continue
		}
		hostName := normalizeHost(host.Target)
		if hostName == "" {
			continue
		}
		tracked++
		findings = append(findings, match(entries, hostName, "wordpress", host.CoreVersion)...)
	}
	findings = append(findings, matchArtifact(runCtx, entries, "wp_plugins", func(slug string) string { return slug })...)
	findings = append(findings, matchArtifact(runCtx, entries, "wp_themes", func(slug string) string { return "theme-" + slug })...)

	if err := runner.AppendCommandLog(runCtx.Run.CommandsLog, runner.Command{
		Name: "wpcve (native)",
		Args: []string{"-hosts", fmt.Sprintf("%d", tracked), "-entries", fmt.Sprintf("%d", len(entries))},
	}); err != nil {
		return nil, fmt.Errorf("failed to write commands log: %w", err)
	}

	if err := writeFindings(runCtx.Run.Path(outputRel), findings); err != nil {
		return nil, err
	}
	if err := runCtx.AddArtifact("wp_cve_findings", modules.Artifact{
		Name: "wp_cve_findings",
		Type: "jsonl",
		Path: outputRel,
	}); err != nil {
		return nil, fmt.Errorf("failed to publish wp_cve_findings: %w", err)
	}
	for _, item := range findings {
		runCtx.EmitFinding(modules.Finding{
			Module:   m.Name(),
			Severity: item.Severity,
			Title:    item.CVEID + " — " + item.Tech,
			Target:   item.Host,
			Detail:   item.Version + " — " + item.Title,
		})
	}
	return &modules.Result{
		Name:   m.Name(),
		Status: "completed",
		OutputFiles: map[string]string{
			"wp_cve_findings": outputRel,
		},
	}, nil
}

// matchArtifact reads a wp_plugins/wp_themes JSONL artifact (when present
// in the run) and returns correlations for each detected slug with a version.
func matchArtifact(runCtx *modules.RunContext, entries []cveEntry, artifact string, key func(slug string) string) []finding {
	pathArtifact, ok := runCtx.GetArtifact(artifact)
	if !ok {
		return nil
	}
	file, err := os.Open(runCtx.Run.Path(pathArtifact.Path))
	if err != nil {
		runCtx.EmitWarning(fmt.Sprintf("wpcve: cannot read %s: %v", artifact, err))
		return nil
	}
	defer func() { _ = file.Close() }()

	var findings []finding
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var record struct {
			URL     string `json:"url"`
			Version string `json:"version"`
			Plugin  string `json:"plugin"`
			Theme   string `json:"theme"`
		}
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			continue
		}
		if record.Version == "" {
			continue
		}
		slug := record.Plugin
		if slug == "" {
			slug = record.Theme
		}
		if slug == "" {
			continue
		}
		hostName := normalizeHost(record.URL)
		if hostName == "" {
			continue
		}
		findings = append(findings, match(entries, hostName, key(slug), record.Version)...)
	}
	return findings
}

func match(entries []cveEntry, host, tech, version string) []finding {
	version = strings.TrimSpace(version)
	if version == "" {
		return nil
	}
	var matches []finding
	for _, entry := range entries {
		if !strings.EqualFold(entry.Tech, tech) {
			continue
		}
		if entry.MinVersion != "" && compareVersions(version, entry.MinVersion) < 0 {
			continue
		}
		if entry.MaxVersion != "" && compareVersions(version, entry.MaxVersion) >= 0 {
			continue
		}
		matches = append(matches, finding{
			Host:      host,
			Tech:      tech,
			Version:   version,
			CVEID:     entry.ID,
			Title:     entry.Title,
			Severity:  entry.Severity,
			CVSS:      entry.CVSS,
			Reference: entry.Reference,
			Note:      entry.Note,
		})
	}
	return matches
}

func normalizeHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
		return strings.ToLower(u.Hostname())
	}
	return strings.ToLower(raw)
}

func loadDataset() ([]cveEntry, error) {
	var entries []cveEntry
	if err := yaml.Unmarshal(datasetYAML, &entries); err != nil {
		return nil, fmt.Errorf("failed to parse embedded WordPress advisory dataset: %w", err)
	}
	return entries, nil
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

func isdigit(r byte) bool {
	return r >= '0' && r <= '9'
}

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

func writeFindings(path string, findings []finding) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("failed to create WordPress CVE findings directory: %w", err)
	}
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create WordPress CVE findings file: %w", err)
	}
	defer func() { _ = file.Close() }()

	for _, item := range findings {
		if err := json.NewEncoder(file).Encode(item); err != nil {
			return fmt.Errorf("failed to write WordPress CVE finding: %w", err)
		}
	}
	return nil
}
