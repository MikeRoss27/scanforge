// Package ctlogs discovers subdomains of the scan target from Certificate
// Transparency logs (crt.sh). It is a native, passive module: it never
// contacts the target, only the public crt.sh service.
//
// Names found this way are leads, not authorization. They are published as
// the "ct_subdomains" scoped text artifact, so the central scope filter
// (RunContext.AddArtifact) drops anything outside the effective scope and
// logs it to scope-rejections.jsonl before dnsx - which merges the artifact
// into the normal subdomain flow, like brute_subdomains - can resolve it.
package ctlogs

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
)

const (
	artifactName = "ct_subdomains"
	outputRel    = "01_subdomains/ct.txt"
	baseURL      = "https://crt.sh/"

	requestTimeout = 90 * time.Second // crt.sh is slow on large domains.
	maxBodyBytes   = 64 << 20         // 64 MiB of JSON is already a huge domain.
	maxNames       = 10000
)

// Module implements modules.Module.
type Module struct {
	fetcher modules.Fetcher
	retry   modules.RetryPolicy
}

// New returns the production module (real HTTP, proxy from the run context).
func New() *Module { return &Module{retry: modules.DefaultRetryPolicy} }

// NewWithFetcher injects the HTTP boundary (tests).
func NewWithFetcher(f modules.Fetcher, retry modules.RetryPolicy) *Module {
	return &Module{fetcher: f, retry: retry}
}

func (m *Module) Name() string { return "ctlogs" }
func (m *Module) Description() string {
	return "Passive subdomain discovery from Certificate Transparency logs (crt.sh)"
}
func (m *Module) Requires() []string { return nil }
func (m *Module) Produces() []string { return []string{artifactName} }

// QueryURL is the crt.sh request for a domain (exported for planning/tests).
func QueryURL(domain string) string {
	return baseURL + "?q=" + url.QueryEscape("%."+domain) + "&output=json"
}

func (m *Module) Run(ctx context.Context, runCtx *modules.RunContext, _ runner.Executor) (*modules.Result, error) {
	domain, err := modules.TargetHost(runCtx.Target)
	if err != nil {
		return nil, err
	}
	outputPath := runCtx.Run.Path(outputRel)
	result := &modules.Result{
		Name:        m.Name(),
		Status:      "completed",
		OutputFiles: map[string]string{artifactName: outputRel},
	}

	// A bare IP has no certificate names to look up under a domain suffix.
	if net.ParseIP(domain) != nil {
		if err := publish(runCtx, outputPath, nil); err != nil {
			return nil, err
		}
		return modules.SkipNotApplicable(result, nil, "target is an IP address, no CT lookup")
	}

	query := QueryURL(domain)
	// Dry run: record the planned request, never touch the network.
	if err := runner.AppendCommandLog(runCtx.Run.CommandsLog, runner.Command{
		Name: "ctlogs (native)",
		Args: []string{"GET", query},
	}); err != nil {
		return nil, fmt.Errorf("failed to write commands log: %w", err)
	}
	if runCtx.DryRun {
		if err := publish(runCtx, outputPath, nil); err != nil {
			return nil, err
		}
		return result, nil
	}

	fetcher := m.fetcher
	if fetcher == nil {
		var closeConn func()
		fetcher, closeConn, err = modules.NewOSINTFetcher(runCtx.Proxy, requestTimeout, maxBodyBytes)
		if err != nil {
			return nil, err
		}
		defer closeConn()
	}

	res, err := modules.FetchWithRetry(ctx, fetcher, query, m.retry)
	if err != nil {
		return nil, fmt.Errorf("crt.sh request failed: %w", err)
	}
	if res.Status != 200 {
		return nil, fmt.Errorf("crt.sh answered HTTP %d", res.Status)
	}
	if res.Truncated {
		return nil, fmt.Errorf("crt.sh response exceeds the %d MiB cap; refusing to parse truncated JSON", maxBodyBytes>>20)
	}
	names, err := ParseNames(res.Body)
	if err != nil {
		return nil, fmt.Errorf("crt.sh returned invalid JSON: %w", err)
	}
	capped := false
	if len(names) > maxNames {
		names, capped = names[:maxNames], true
	}
	if err := publish(runCtx, outputPath, names); err != nil {
		return nil, err
	}
	if capped {
		runCtx.EmitWarning(fmt.Sprintf("ctlogs: result capped at %d names", maxNames))
	}
	if len(names) == 0 {
		return modules.SkipNotApplicable(result, nil, "no certificate names found")
	}
	return result, nil
}

func publish(runCtx *modules.RunContext, path string, names []string) error {
	content := ""
	if len(names) > 0 {
		content = strings.Join(names, "\n") + "\n"
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write CT names: %w", err)
	}
	// Scoped: the central filter drops out-of-scope names and logs them.
	if err := runCtx.AddArtifact(artifactName, modules.Artifact{
		Name:   artifactName,
		Type:   "text",
		Path:   outputRel,
		Scoped: true,
	}); err != nil {
		return fmt.Errorf("failed to publish CT names: %w", err)
	}
	return nil
}

type crtEntry struct {
	CommonName string `json:"common_name"`
	NameValue  string `json:"name_value"`
}

// ParseNames extracts the sorted, de-duplicated, lowercase host names from a
// crt.sh JSON array. Wildcard prefixes are stripped ("*.a.example.com" yields
// "a.example.com"), newline-joined name_value fields are split, and e-mail
// SANs and anything that is not a plausible DNS name are dropped. No scope
// filtering happens here on purpose: the artifact filter does it and audits
// the rejections.
func ParseNames(body []byte) ([]string, error) {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return nil, nil // crt.sh answers an empty body when nothing matches.
	}
	var entries []crtEntry
	if err := json.Unmarshal([]byte(trimmed), &entries); err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	for _, e := range entries {
		for _, raw := range append(strings.Split(e.NameValue, "\n"), e.CommonName) {
			if name, ok := normalizeName(raw); ok {
				seen[name] = struct{}{}
			}
		}
	}
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, nil
}

func normalizeName(raw string) (string, bool) {
	name := strings.ToLower(strings.TrimSpace(raw))
	for strings.HasPrefix(name, "*.") {
		name = name[2:]
	}
	name = strings.TrimSuffix(name, ".")
	if name == "" || len(name) > 253 || net.ParseIP(name) != nil || !strings.Contains(name, ".") {
		return "", false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '_' {
				return "", false
			}
		}
	}
	return name, true
}
