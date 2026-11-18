// Package wpexposure checks WordPress hosts for the exposures wpscan reports
// out of the box: wp-config.php backups/variant files, debug.log, default
// wp-admin setup pages, directory listings, and developer leftovers
// (.git/HEAD, .env, phpinfo). Every finding is recorded with the evidence
// URL and the matched body marker; sensitive file contents are never stored.
package wpexposure

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/modules/wpcore"
	"github.com/MikeRoss27/scanforge/internal/runner"
)

const (
	outputRel      = wpcore.OutputDir + "/wp-exposure.jsonl"
	reportName     = "wp_exposure"
	workerCount    = 8
	requestTimeout = 15 * time.Second
	maxBodyBytes   = 256 * 1024
	maxHosts       = 100
)

type Finding struct {
	URL        string `json:"url"`
	Check      string `json:"check"`
	Severity   string `json:"severity"`
	Title      string `json:"title"`
	Detail     string `json:"detail"`
	Confidence string `json:"confidence"`
}

type exposureCheck struct {
	name     string
	path     string
	severity string
	title    string
	marker   string // lower-cased substring that must appear in the body
}

var exposureChecks = []exposureCheck{
	{name: "wp-config-backup", path: "/wp-config.php.bak", severity: "critical", title: "Exposed wp-config.php backup", marker: "db_password"},
	{name: "wp-config-backup", path: "/wp-config.php.old", severity: "critical", title: "Exposed wp-config.php backup", marker: "db_password"},
	{name: "wp-config-backup", path: "/wp-config.php.save", severity: "critical", title: "Exposed wp-config.php backup", marker: "db_password"},
	{name: "wp-config-backup", path: "/wp-config.php~", severity: "critical", title: "Exposed wp-config.php backup", marker: "db_password"},
	{name: "wp-config-backup", path: "/wp-config.php.swp", severity: "critical", title: "Exposed wp-config.php swap file", marker: "db_password"},
	{name: "wp-config-backup", path: "/wp-config.php.txt", severity: "critical", title: "Exposed wp-config.php backup", marker: "db_password"},
	{name: "wp-config-backup", path: "/wp-config.bak", severity: "critical", title: "Exposed wp-config backup", marker: "db_password"},
	{name: "debug-log", path: "/wp-content/debug.log", severity: "high", title: "WordPress debug.log exposed", marker: "fatal error|stack trace|uncaught|parse error|wordpress database error"},
	{name: "install-php", path: "/wp-admin/install.php", severity: "medium", title: "WordPress install page exposed", marker: "wordpress"},
	{name: "setup-config", path: "/wp-admin/setup-config.php", severity: "medium", title: "WordPress setup page exposed", marker: "wordpress"},
	{name: "readme-html", path: "/readme.html", severity: "low", title: "WordPress readme.html exposed", marker: "wordpress"},
	{name: "license-txt", path: "/license.txt", severity: "low", title: "WordPress license.txt exposed", marker: "wordpress"},
	{name: "uploads-listing", path: "/wp-content/uploads/", severity: "medium", title: "Directory listing in wp-content/uploads", marker: "index of"},
	{name: "plugins-listing", path: "/wp-content/plugins/", severity: "medium", title: "Directory listing in wp-content/plugins", marker: "index of"},
	{name: "git-head", path: "/.git/HEAD", severity: "high", title: "Exposed .git repository (HEAD)", marker: "ref:"},
	{name: "env-file", path: "/.env", severity: "high", title: "Exposed .env file", marker: "db_"},
	{name: "phpinfo", path: "/phpinfo.php", severity: "high", title: "Exposed phpinfo()", marker: "phpinfo"},
	{name: "phpinfo", path: "/info.php", severity: "high", title: "Exposed phpinfo()", marker: "phpinfo"},
}

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Name() string { return "wpexposure" }
func (m *Module) Description() string {
	return "Checks WordPress hosts for exposed backups, debug logs, setup pages, listings and developer leftovers"
}
func (m *Module) Requires() []string { return []string{"wp_fingerprint"} }
func (m *Module) Produces() []string { return []string{reportName} }

type probeJob struct {
	host  wpcore.FingerprintRecord
	check exposureCheck
}

func (m *Module) Run(ctx context.Context, runCtx *modules.RunContext, _ runner.Executor) (*modules.Result, error) {
	fpArt, err := runCtx.MustArtifact("wp_fingerprint")
	if err != nil {
		return nil, err
	}
	hosts, err := wpcore.LoadFingerprint(runCtx.Run.Path(fpArt.Path))
	if err != nil {
		return nil, fmt.Errorf("failed to read wp_fingerprint: %w", err)
	}
	if len(hosts) == 0 {
		runCtx.EmitWarning("wpexposure: no WordPress hosts identified; skipping")
		if err := writeFindings(runCtx.Run.Path(outputRel), nil); err != nil {
			return nil, err
		}
		return finish(m, runCtx)
	}
	if maxHosts > 0 && len(hosts) > maxHosts {
		hosts = hosts[:maxHosts]
	}
	if err := runner.AppendCommandLog(runCtx.Run.CommandsLog, runner.Command{
		Name: "wpexposure (native)",
		Args: []string{"-hosts", fmt.Sprintf("%d", len(hosts)), "-checks", fmt.Sprintf("%d", len(exposureChecks))},
	}); err != nil {
		return nil, fmt.Errorf("failed to write commands log: %w", err)
	}

	if errs := validateChecks(); errs != nil {
		return nil, errs
	}

	var findings []Finding
	if !runCtx.DryRun {
		client, closeConn, err := modules.NewProxyClient(runCtx.Proxy, requestTimeout)
		if err != nil {
			return nil, err
		}
		defer closeConn()

		var wg sync.WaitGroup
		var mu sync.Mutex
		sem := make(chan struct{}, workerCount)
		for _, host := range hosts {
			for _, check := range exposureChecks {
				wg.Add(1)
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					wg.Done()
					wg.Wait()
					return nil, ctx.Err()
				}
				go func(host wpcore.FingerprintRecord, check exposureCheck) {
					defer wg.Done()
					defer func() { <-sem }()

					target := host.Target + check.path
					status, body, _, err := modules.WPBody(ctx, client, target, runCtx.Headers, maxBodyBytes)
					if err != nil || status != http.StatusOK || len(body) == 0 {
						return
					}
					lower := strings.ToLower(string(body))
					matched := false
					for _, marker := range strings.Split(check.marker, "|") {
						if strings.Contains(lower, strings.ToLower(marker)) {
							matched = true
							break
						}
					}
					if !matched {
						return
					}
					mu.Lock()
					findings = append(findings, Finding{
						URL:        target,
						Check:      check.name,
						Severity:   check.severity,
						Title:      check.title,
						Detail:     "Exposed at " + target,
						Confidence: "high",
					})
					mu.Unlock()
				}(host, check)
			}
		}
		wg.Wait()

		for _, f := range findings {
			runCtx.EmitFinding(modules.Finding{
				Module:   m.Name(),
				Severity: f.Severity,
				Title:    f.Title,
				Target:   host(f.URL),
				Detail:   f.Detail,
			})
		}
	}

	sortFindings(findings)
	if err := writeFindings(runCtx.Run.Path(outputRel), findings); err != nil {
		return nil, err
	}
	return finish(m, runCtx)
}

func host(target string) string {
	if i := strings.Index(target, "://"); i >= 0 {
		rest := target[i+3:]
		if j := strings.Index(rest, "/"); j >= 0 {
			return target[:i+3+j]
		}
		return target
	}
	return target
}

func sortFindings(items []Finding) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].URL == items[j].URL {
			return items[i].Check < items[j].Check
		}
		return items[i].URL < items[j].URL
	})
}

func finish(m *Module, runCtx *modules.RunContext) (*modules.Result, error) {
	if err := runCtx.AddArtifact(reportName, modules.Artifact{
		Name: reportName,
		Type: "jsonl",
		Path: outputRel,
	}); err != nil {
		return nil, fmt.Errorf("failed to publish wp_exposure: %w", err)
	}
	return &modules.Result{
		Name:   m.Name(),
		Status: "completed",
		OutputFiles: map[string]string{
			reportName: outputRel,
		},
	}, nil
}

func writeFindings(path string, items []Finding) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("failed to create WordPress exposure directory: %w", err)
	}
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create WordPress exposure file: %w", err)
	}
	defer func() { _ = file.Close() }()

	for _, item := range items {
		if err := json.NewEncoder(file).Encode(item); err != nil {
			return fmt.Errorf("failed to write WordPress exposure finding: %w", err)
		}
	}
	return nil
}

func validateChecks() error {
	for i, check := range exposureChecks {
		if check.name == "" || check.path == "" || check.severity == "" || check.marker == "" {
			return fmt.Errorf("exposure check %d is incomplete", i)
		}
		if !strings.HasPrefix(check.path, "/") {
			return fmt.Errorf("exposure check %q path must start with /", check.name)
		}
	}
	return nil
}
