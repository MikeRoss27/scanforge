// Package wpusers enumerates WordPress usernames from the public probes:
// ?author=N redirects, the REST API users endpoint and the per-author feeds.
// These are the same signals wpscan uses by default (--enumerate u).
package wpusers

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
	outputRel      = wpcore.OutputDir + "/wp-users.jsonl"
	reportName     = "wp_users"
	fpFile         = wpcore.OutputDir + "/wp-fingerprint.jsonl"
	workerCount    = 6
	requestTimeout = 15 * time.Second
	maxBodyBytes   = 256 * 1024
	maxHosts       = 100
	maxAuthorIDs   = 10
)

type Finding struct {
	URL         string `json:"url"`
	Login       string `json:"login"`
	DisplayName string `json:"display_name,omitempty"`
	UserID      int    `json:"user_id,omitempty"`
	Source      string `json:"source"`
	Confidence  string `json:"confidence"`
	Evidence    string `json:"evidence,omitempty"`
}

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Name() string { return "wpusers" }
func (m *Module) Description() string {
	return "Enumerates WordPress usernames (?author=N redirects, REST API /wp/v2/users) for credential attacks and access review"
}
func (m *Module) Requires() []string { return []string{"wp_fingerprint"} }
func (m *Module) Produces() []string { return []string{reportName} }

var authorSlugRe = regexp.MustCompile(`/author/([A-Za-z0-9_.-]+)`)

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
		if err := writeFindings(runCtx.Run.Path(outputRel), nil); err != nil {
			return nil, err
		}
		res, err := finish(m, runCtx)
		return modules.SkipNotApplicable(res, err, "no WordPress detected")
	}
	if maxHosts > 0 && len(hosts) > maxHosts {
		hosts = hosts[:maxHosts]
	}
	if err := runner.AppendCommandLog(runCtx.Run.CommandsLog, runner.Command{
		Name: "wpusers (native)",
		Args: []string{"-hosts", fmt.Sprintf("%d", len(hosts)), "-author-ids", fmt.Sprintf("%d", maxAuthorIDs)},
	}); err != nil {
		return nil, fmt.Errorf("failed to write commands log: %w", err)
	}

	found := map[string]Finding{} // login per host -> record
	if !runCtx.DryRun {
		client, closeConn, err := modules.NewProxyClient(runCtx.Proxy, requestTimeout)
		if err != nil {
			return nil, err
		}
		defer closeConn()

		// ?author=N redirect probes: Location header carries the slug.
		noRedirect := &http.Client{Timeout: requestTimeout, Transport: client.Transport, CheckRedirect: modules.NoRedirectCheckRedirect}
		var mu sync.Mutex
		var wg sync.WaitGroup
		sem := make(chan struct{}, workerCount)
		for _, host := range hosts {
			for id := 1; id <= maxAuthorIDs; id++ {
				wg.Add(1)
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					wg.Done()
					wg.Wait()
					return nil, ctx.Err()
				}
				go func(h wpcore.FingerprintRecord, authorID int) {
					defer wg.Done()
					defer func() { <-sem }()

					target := h.Target + "/?author=" + fmt.Sprintf("%d", authorID)
					req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
					if err != nil {
						return
					}
					modules.ApplyHeaders(req, runCtx.Headers)
					resp, err := noRedirect.Do(req)
					if err != nil {
						return
					}
					defer func() { _ = resp.Body.Close() }()
					location := resp.Header.Get("Location")
					m := authorSlugRe.FindStringSubmatch(location)
					if m == nil {
						return
					}
					login := strings.ToLower(m[1])
					mu.Lock()
					recordKey := h.Target + "|" + login
					if _, dup := found[recordKey]; !dup {
						found[recordKey] = Finding{
							URL:        h.Target,
							Login:      login,
							UserID:     authorID,
							Source:     "author-redirect",
							Confidence: "high",
							Evidence:   "Location: " + location,
						}
					}
					mu.Unlock()
				}(host, id)
			}
		}
		wg.Wait()

		// REST API users endpoint.
		for _, host := range hosts {
			_, body, _, _ := modules.WPBody(ctx, client, host.Target+"/wp-json/wp/v2/users", runCtx.Headers, maxBodyBytes)
			if body == nil {
				continue
			}
			var users []struct {
				ID   int    `json:"id"`
				Name string `json:"name"`
				Slug string `json:"slug"`
				Link string `json:"link"`
			}
			if err := json.Unmarshal(body, &users); err != nil {
				continue
			}
			mu.Lock()
			for _, u := range users {
				login := strings.ToLower(strings.TrimSpace(u.Slug))
				if login == "" {
					continue
				}
				key := host.Target + "|" + login
				if existing, ok := found[key]; ok {
					// found holds values, not pointers: the merge must be
					// written back explicitly or it's silently discarded.
					if existing.DisplayName == "" {
						existing.DisplayName = u.Name
					}
					existing.Confidence = "high"
					found[key] = existing
					continue
				}
				found[key] = Finding{
					URL:         host.Target,
					Login:       login,
					DisplayName: u.Name,
					UserID:      u.ID,
					Source:      "rest-api",
					Confidence:  "high",
					Evidence:    "/wp-json/wp/v2/users",
				}
			}
			mu.Unlock()
		}
	}

	findings := make([]Finding, 0, len(found))
	for _, item := range found {
		findings = append(findings, item)
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].URL != findings[j].URL {
			return findings[i].URL < findings[j].URL
		}
		return findings[i].Login < findings[j].Login
	})

	for _, f := range findings {
		runCtx.EmitFinding(modules.Finding{
			Module:   m.Name(),
			Severity: "info",
			Title:    "WordPress user enumerated",
			Target:   f.URL,
			Detail:   f.Login,
		})
	}

	if err := writeFindings(runCtx.Run.Path(outputRel), findings); err != nil {
		return nil, err
	}
	return finish(m, runCtx)
}

func finish(m *Module, runCtx *modules.RunContext) (*modules.Result, error) {
	if err := runCtx.AddArtifact(reportName, modules.Artifact{
		Name: reportName,
		Type: "jsonl",
		Path: outputRel,
	}); err != nil {
		return nil, fmt.Errorf("failed to publish wp_users: %w", err)
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
		return fmt.Errorf("failed to create WordPress users directory: %w", err)
	}
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create WordPress users file: %w", err)
	}
	defer func() { _ = file.Close() }()

	for _, item := range items {
		if err := json.NewEncoder(file).Encode(item); err != nil {
			return fmt.Errorf("failed to write WordPress user: %w", err)
		}
	}
	return nil
}
