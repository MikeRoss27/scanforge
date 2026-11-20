// Package wpxmlrpc probes the WordPress XML-RPC endpoint. It never sends
// credential probes or multicall fan-out: a single system.listMethods call is
// enough to tell whether XML-RPC is enabled, which methods it exposes, and
// whether pingback (SSRF-relevant) and system.multicall (brute-amplification)
// are available. The pingback signal is reported as informational only — no
// rebinding is ever attempted.
package wpxmlrpc

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
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
	outputRel      = wpcore.OutputDir + "/wp-xmlrpc.jsonl"
	reportName     = "wp_xmlrpc"
	workerCount    = 8
	requestTimeout = 15 * time.Second
	maxBodyBytes   = 512 * 1024
	maxHosts       = 100

	listMethodsCall = `<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>`
)

type Finding struct {
	URL          string   `json:"url"`
	Enabled      bool     `json:"enabled"`
	Methods      []string `json:"methods,omitempty"`
	HasMulticall bool     `json:"has_multicall"`
	Pingback     bool     `json:"pingback"`
	Evidence     string   `json:"evidence,omitempty"`
}

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Name() string { return "wpxmlrpc" }
func (m *Module) Description() string {
	return "Probes /xmlrpc.php: enabled state, exposed methods, multicall and pingback availability"
}
func (m *Module) Requires() []string { return []string{"wp_fingerprint"} }
func (m *Module) Produces() []string { return []string{reportName} }

type listMethodsResponse struct {
	Params struct {
		Param []struct {
			Value struct {
				Array struct {
					Data struct {
						Member []struct {
							Value struct {
								String string `xml:"string"`
							} `xml:"value"`
						} `xml:"member"`
					} `xml:"data"`
				} `xml:"array"`
			} `xml:"value"`
		} `xml:"param"`
	} `xml:"params"`
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
		runCtx.EmitWarning("wpxmlrpc: no WordPress hosts identified; skipping")
		if err := writeFindings(runCtx.Run.Path(outputRel), nil); err != nil {
			return nil, err
		}
		return finish(m, runCtx)
	}
	if maxHosts > 0 && len(hosts) > maxHosts {
		hosts = hosts[:maxHosts]
	}
	if err := runner.AppendCommandLog(runCtx.Run.CommandsLog, runner.Command{
		Name: "wpxmlrpc (native)",
		Args: []string{"-hosts", fmt.Sprintf("%d", len(hosts))},
	}); err != nil {
		return nil, fmt.Errorf("failed to write commands log: %w", err)
	}

	findings := []Finding{}
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
			wg.Add(1)
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				wg.Done()
				wg.Wait()
				return nil, ctx.Err()
			}
			go func(host wpcore.FingerprintRecord) {
				defer wg.Done()
				defer func() { <-sem }()

				result := probeXMLRPC(ctx, client, runCtx, host)
				mu.Lock()
				findings = append(findings, result)
				mu.Unlock()
			}(host)
		}
		wg.Wait()

		for _, item := range findings {
			if !item.Enabled {
				continue
			}
			runCtx.EmitFinding(modules.Finding{
				Module:   m.Name(),
				Severity: "medium",
				Title:    "XML-RPC endpoint enabled",
				Target:   item.URL,
				Detail:   fmt.Sprintf("%d methods; multicall=%t; pingback=%t", len(item.Methods), item.HasMulticall, item.Pingback),
			})
		}
	}

	sort.Slice(findings, func(i, j int) bool { return findings[i].URL < findings[j].URL })
	if err := writeFindings(runCtx.Run.Path(outputRel), findings); err != nil {
		return nil, err
	}
	return finish(m, runCtx)
}

func probeXMLRPC(ctx context.Context, client *http.Client, runCtx *modules.RunContext, host wpcore.FingerprintRecord) Finding {
	target := host.Target + "/xmlrpc.php"
	result := Finding{URL: target}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(listMethodsCall))
	if err != nil {
		return result
	}
	// Set Content-Type first so operator-provided -H can override it.
	req.Header.Set("Content-Type", "text/xml")
	modules.ApplyHeaders(req, runCtx.Headers)

	resp, err := client.Do(req)
	if err != nil {
		return result
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return result
	}

	bodyStr := strings.TrimSpace(string(body))
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		// Some WAFs block XML-RPC access: treat as present but blocked.
		result.Enabled = false
		result.Evidence = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return result
	}
	if !strings.Contains(bodyStr, "<?xml") && !strings.Contains(bodyStr, "<params>") && !strings.Contains(bodyStr, "methodResponse") {
		// Not a valid XML-RPC response (or endpoint that declines cleanly).
		if resp.StatusCode == http.StatusOK && strings.Contains(strings.ToLower(bodyStr), "xml-rpc") {
			// WP's default reply for GET (or wrong Content-Type): XML-RPC exists.
			result.Enabled = true
			result.Evidence = "xml-rpc endpoint responds (non-listMethods reply)"
			return result
		}
		return result
	}

	methods := parseMethods(bodyStr)
	if len(methods) == 0 {
		// Could not parse; still enabled because the server answered.
		result.Enabled = true
		result.Evidence = "xml-rpc endpoint responds"
		return result
	}
	result.Enabled = true
	result.Methods = methods
	for _, method := range methods {
		switch method {
		case "system.multicall":
			result.HasMulticall = true
		case "pingback.ping":
			result.Pingback = true
		}
	}
	result.Evidence = fmt.Sprintf("system.listMethods → %d methods", len(methods))
	return result
}

func parseMethods(body string) []string {
	var parsed listMethodsResponse
	if err := xml.Unmarshal([]byte(body), &parsed); err != nil {
		return nil
	}
	var methods []string
	for _, param := range parsed.Params.Param {
		for _, member := range param.Value.Array.Data.Member {
			name := strings.TrimSpace(member.Value.String)
			if name != "" {
				methods = append(methods, name)
			}
		}
	}
	sort.Strings(methods)
	return methods
}

func finish(m *Module, runCtx *modules.RunContext) (*modules.Result, error) {
	if err := runCtx.AddArtifact(reportName, modules.Artifact{
		Name: reportName,
		Type: "jsonl",
		Path: outputRel,
	}); err != nil {
		return nil, fmt.Errorf("failed to publish wp_xmlrpc: %w", err)
	}
	return &modules.Result{
		Name:   m.Name(),
		Status: "completed",
		// Keep output map under the module name as well for discoverability.
		OutputFiles: map[string]string{
			reportName: outputRel,
		},
	}, nil
}

func writeFindings(path string, items []Finding) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("failed to create WordPress xmlrpc directory: %w", err)
	}
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create WordPress xmlrpc file: %w", err)
	}
	defer func() { _ = file.Close() }()

	for _, item := range items {
		if err := json.NewEncoder(file).Encode(item); err != nil {
			return fmt.Errorf("failed to write WordPress xmlrpc result: %w", err)
		}
	}
	return nil
}
