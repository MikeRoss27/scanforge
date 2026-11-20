// Package wpdetect identifies WordPress installations behind the discovered
// alive URLs and extracts the core version when possible. It never sends
// fuzzing traffic: it only fetches the homepage, the RSS feed, the bundled
// readme.html and the REST index — the same passive signals wpscan uses in
// its default mode.
package wpdetect

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/modules/wpcore"
	"github.com/MikeRoss27/scanforge/internal/runner"
)

const (
	fingerprintFile = wpcore.OutputDir + "/wp-fingerprint.jsonl"
	workerCount     = 8
	requestTimeout  = 20 * time.Second
	maxBodyBytes    = 512 * 1024
	maxHosts        = 100
)

type Finding = wpcore.FingerprintRecord

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Name() string { return "wpdetect" }
func (m *Module) Description() string {
	return "Detects WordPress installations and extracts the core version from passive signals"
}
func (m *Module) Requires() []string { return []string{"alive_urls"} }
func (m *Module) Produces() []string { return []string{"wp_fingerprint"} }

var (
	generatorRe = regexp.MustCompile(`(?i)<meta[^>]+name=["']generator["'][^>]+content=["'][^"']*WordPress[^"']*?(\d+\.\d+(?:\.\d+)?)?`)
	feedGenRe   = regexp.MustCompile(`(?i)<generator>[^<]*?wordpress\.org/\?v=(\d+\.\d+(?:\.\d+)?)`)
	readmeRe    = regexp.MustCompile(`(?i)Version\s+(\d+\.\d+(?:\.\d+)?)`)
)

func (m *Module) Run(ctx context.Context, runCtx *modules.RunContext, _ runner.Executor) (*modules.Result, error) {
	inputArt, err := runCtx.MustArtifact("alive_urls")
	if err != nil {
		return nil, err
	}
	inputFile := runCtx.Run.Path(inputArt.Path)

	hosts, err := modules.ReadAliveHosts(inputFile, maxHosts)
	if err != nil {
		return nil, fmt.Errorf("failed to read alive URLs: %w", err)
	}

	if err := runner.AppendCommandLog(runCtx.Run.CommandsLog, runner.Command{
		Name: "wpdetect (native)",
		Args: []string{"-hosts", fmt.Sprintf("%d", len(hosts)), "-mode", "passive"},
	}); err != nil {
		return nil, fmt.Errorf("failed to write commands log: %w", err)
	}

	findings := make([]Finding, 0, len(hosts))
	if !runCtx.DryRun {
		client, closeConn, err := modules.NewProxyClient(runCtx.Proxy, requestTimeout)
		if err != nil {
			return nil, err
		}
		defer closeConn()

		var mu sync.Mutex
		var wg sync.WaitGroup
		sem := make(chan struct{}, workerCount)
		for _, host := range hosts {
			wg.Add(1)
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				wg.Done()
				wg.Wait()
				return nil, ctx.Err()
			}
			go func(host string) {
				defer wg.Done()
				defer func() { <-sem }()

				result := ProbeHost(ctx, client, runCtx, host)
				mu.Lock()
				findings = append(findings, result)
				mu.Unlock()
			}(host)
		}
		wg.Wait()

		sort.Slice(findings, func(i, j int) bool { return findings[i].Target < findings[j].Target })

		for _, finding := range findings {
			if finding.IsWordPress {
				detail := "WordPress"
				if finding.CoreVersion != "" {
					detail = "WordPress " + finding.CoreVersion
				}
				runCtx.EmitFinding(modules.Finding{
					Module:   m.Name(),
					Severity: "info",
					Title:    "WordPress detected",
					Target:   finding.Target,
					Detail:   detail,
				})
			}
		}
	} else {
		for _, host := range hosts {
			findings = append(findings, Finding{Target: host, FetchedAt: time.Now().UTC().Format(time.RFC3339)})
		}
	}

	if err := writeFindings(runCtx.Run.Path(fingerprintFile), findings); err != nil {
		return nil, err
	}
	if err := runCtx.AddArtifact("wp_fingerprint", modules.Artifact{
		Name: "wp_fingerprint",
		Type: "jsonl",
		Path: fingerprintFile,
	}); err != nil {
		return nil, fmt.Errorf("failed to publish wp_fingerprint: %w", err)
	}
	return &modules.Result{
		Name:   m.Name(),
		Status: "completed",
		OutputFiles: map[string]string{
			"wp_fingerprint": fingerprintFile,
		},
	}, nil
}

// ProbeHost runs the module's passive detection signals (homepage generator
// meta, RSS feed, readme.html, REST index) against a single host. Exported
// so callers outside the module — the app layer's pre-scan WordPress
// suggestion, in particular — can reuse the exact same detection logic
// without needing the full Run() artifact pipeline.
func ProbeHost(ctx context.Context, client *http.Client, runCtx *modules.RunContext, host string) Finding {
	result := Finding{Target: host, FetchedAt: time.Now().UTC().Format(time.RFC3339)}

	_, homepageBody, _, _ := modules.WPBody(ctx, client, host+"/", runCtx.Headers, maxBodyBytes)
	if homepageBody != nil {
		lower := strings.ToLower(string(homepageBody))
		if m := generatorRe.FindSubmatch(homepageBody); m != nil {
			result.IsWordPress = true
			result.Sources = append(result.Sources, "generator")
			if v := strings.TrimSpace(string(m[1])); v != "" {
				result.CoreVersion = v
			}
		} else if strings.Contains(lower, "/wp-content/") || strings.Contains(lower, "/wp-includes/") {
			result.IsWordPress = true
			result.Sources = append(result.Sources, "paths")
		}
	}

	_, feedBody, _, _ := modules.WPBody(ctx, client, host+"/?feed=rss2", runCtx.Headers, maxBodyBytes)
	if feedBody != nil {
		if m := feedGenRe.FindSubmatch(feedBody); m != nil {
			result.IsWordPress = true
			result.Sources = append(result.Sources, "feed")
			if result.CoreVersion == "" {
				result.CoreVersion = strings.TrimSpace(string(m[1]))
			}
		}
	}

	status, readmeBody, _, _ := modules.WPBody(ctx, client, host+"/readme.html", runCtx.Headers, maxBodyBytes)
	if status == http.StatusOK && readmeBody != nil {
		if m := readmeRe.FindSubmatch(readmeBody); m != nil && looksLikeWordPressReadme(readmeBody) {
			result.IsWordPress = true
			result.Sources = append(result.Sources, "readme")
			if result.CoreVersion == "" {
				result.CoreVersion = strings.TrimSpace(string(m[1]))
			}
		}
	}

	status, restBody, restHeader, _ := modules.WPBody(ctx, client, host+"/wp-json/", runCtx.Headers, maxBodyBytes)
	if status == http.StatusOK && restBody != nil {
		var index struct {
			Namespaces []string `json:"namespaces"`
		}
		if json.Unmarshal(restBody, &index) == nil {
			for _, ns := range index.Namespaces {
				if strings.HasPrefix(ns, "wp/") {
					result.IsWordPress = true
					result.Sources = append(result.Sources, "rest-api")
					break
				}
			}
		} else if strings.Contains(strings.ToLower(string(restBody)), "wp-json") || restHeader.Get("X-WP-Total") != "" {
			result.IsWordPress = true
			result.Sources = append(result.Sources, "rest-api")
		}
	}

	switch {
	case result.CoreVersion != "" && len(result.Sources) >= 2:
		result.Confidence = "high"
	case result.IsWordPress:
		result.Confidence = "medium"
	default:
		result.Confidence = "low"
	}
	if len(result.Sources) == 0 {
		result.Sources = []string{}
	}
	sort.Strings(result.Sources)
	return result
}

func looksLikeWordPressReadme(body []byte) bool {
	lower := strings.ToLower(string(body))
	return strings.Contains(lower, "wordpress") && (strings.Contains(lower, "version") || strings.Contains(lower, "license"))
}

func writeFindings(path string, items []Finding) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("failed to create WordPress fingerprint directory: %w", err)
	}
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create WordPress fingerprint file: %w", err)
	}
	defer func() { _ = file.Close() }()

	// Non-WordPress hosts are recorded with is_wordpress=false so downstream
	// modules can trust the artifact to cover every probed host.
	for _, item := range items {
		if err := json.NewEncoder(file).Encode(item); err != nil {
			return fmt.Errorf("failed to write WordPress fingerprint: %w", err)
		}
	}
	return nil
}
