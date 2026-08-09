// Package httpcheck performs lightweight HTTP security header checks on the
// discovered attack surface and reports hardening gaps (missing CSP, HSTS,
// clickjacking protections, unsafe cookies) as low/info findings.
package httpcheck

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
)

const (
	workerCount    = 10
	requestTimeout = 15 * time.Second
	maxBodyBytes   = 1 << 20
	outputRel      = "06_vulns/http-checks.jsonl"
)

// check is one hardening gap found on one URL.
type check struct {
	URL      string `json:"url"`
	Check    string `json:"check"`
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
}

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Name() string { return "httpcheck" }
func (m *Module) Description() string {
	return "Checks HTTP security headers (CSP, HSTS, clickjacking, cookies) on the discovered attack surface"
}
func (m *Module) Requires() []string { return []string{"attack_surface_urls"} }
func (m *Module) Produces() []string { return []string{"http_checks"} }

func (m *Module) Run(ctx context.Context, runCtx *modules.RunContext, _ runner.Executor) (*modules.Result, error) {
	inputArt, err := runCtx.MustArtifact("attack_surface_urls")
	if err != nil {
		return nil, err
	}
	inputFile := runCtx.Run.Path(inputArt.Path)

	urls, err := readURLs(inputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read attack surface: %w", err)
	}
	if !runCtx.DryRun {
		if _, statErr := os.Stat(inputFile); os.IsNotExist(statErr) {
			// In a real run a missing attack surface means the upstream
			// modules produced nothing; completing silently would hide it.
			return nil, fmt.Errorf("attack surface file %q is missing (upstream modules produced no output)", inputFile)
		}
	}

	if err := runner.AppendCommandLog(runCtx.Run.CommandsLog, runner.Command{
		Name: "httpcheck (native)",
		Args: []string{
			"-input", inputFile,
			"-urls", fmt.Sprintf("%d", len(urls)),
			"-workers", fmt.Sprintf("%d", workerCount),
		},
	}); err != nil {
		return nil, fmt.Errorf("failed to write commands log: %w", err)
	}

	var checks []check
	if !runCtx.DryRun && len(urls) > 0 {
		checks, err = runChecks(ctx, runCtx, urls)
		if err != nil {
			return nil, err
		}
	}

	// Header hardening is host-level: a missing header on one URL of a host
	// implies it on the others, so report each check at most once per host.
	seen := make(map[string]bool)
	deduped := checks[:0]
	for _, c := range checks {
		host := c.URL
		if u, err := url.Parse(c.URL); err == nil && u.Host != "" {
			host = u.Host
		}
		key := c.Check + "|" + host
		if seen[key] {
			continue
		}
		seen[key] = true
		deduped = append(deduped, c)
	}
	checks = deduped

	sort.Slice(checks, func(i, j int) bool {
		if checks[i].URL != checks[j].URL {
			return checks[i].URL < checks[j].URL
		}
		return checks[i].Check < checks[j].Check
	})

	if err := writeChecks(runCtx.Run.Path(outputRel), checks); err != nil {
		return nil, err
	}

	if err := runCtx.AddArtifact("http_checks", modules.Artifact{
		Name: "http_checks",
		Type: "jsonl",
		Path: outputRel,
	}); err != nil {
		return nil, fmt.Errorf("failed to publish HTTP checks: %w", err)
	}

	return &modules.Result{
		Name:   m.Name(),
		Status: "completed",
		OutputFiles: map[string]string{
			"http_checks": outputRel,
		},
	}, nil
}

func runChecks(ctx context.Context, runCtx *modules.RunContext, urls []string) ([]check, error) {
	transport := &http.Transport{}
	if runCtx.Proxy != "" {
		parsed, err := url.Parse(runCtx.Proxy)
		if err != nil {
			return nil, fmt.Errorf("failed to parse proxy %q: %w", runCtx.Proxy, err)
		}
		transport.Proxy = http.ProxyURL(parsed)
	}
	client := &http.Client{Timeout: requestTimeout, Transport: transport}
	defer transport.CloseIdleConnections()

	var (
		mu     sync.Mutex
		checks []check
		wg     sync.WaitGroup
		sem    = make(chan struct{}, workerCount)
	)
	for _, target := range urls {
		wg.Add(1)
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			// Stop scheduling new requests, but still wait for the in-flight
			// ones: they share ctx, abort quickly, and draining them here
			// avoids racing the caller's read of checks.
			wg.Done()
			wg.Wait()
			return checks, nil
		}
		go func(target string) {
			defer wg.Done()
			defer func() { <-sem }()

			found := inspectURL(ctx, client, target, runCtx.Headers)
			if len(found) == 0 {
				return
			}
			mu.Lock()
			checks = append(checks, found...)
			mu.Unlock()
		}(target)
	}
	wg.Wait()
	return checks, nil
}

// inspectURL fetches target and derives security header findings. Fetching is
// best effort: transport errors or non-HTTP responses yield no findings.
func inspectURL(ctx context.Context, client *http.Client, target string, headers []string) []check {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil
	}
	applyHeaders(req, headers)

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBodyBytes))

	// Only attribute the final response to the requested host: a cross-host
	// redirect (SSO, CDN, mirror) would otherwise report third-party headers
	// against our target.
	if resp.Request != nil && resp.Request.URL != nil {
		if requested, err := url.Parse(target); err == nil {
			if !strings.EqualFold(resp.Request.URL.Host, requested.Host) {
				return nil
			}
		}
	}

	return evaluateHeaders(target, resp.Header)
}

func evaluateHeaders(target string, header http.Header) []check {
	var checks []check

	// CSP: missing entirely, or present without clickjacking protection.
	csp := header.Get("Content-Security-Policy")
	xfo := header.Get("X-Frame-Options")
	if csp == "" {
		checks = append(checks, check{target, "missing-csp", "info", "Content-Security-Policy header is missing"})
	} else if !strings.Contains(strings.ToLower(csp), "frame-ancestors") && xfo == "" {
		checks = append(checks, check{target, "clickjacking-unprotected", "low", "No frame-ancestors CSP directive nor X-Frame-Options header"})
	}

	// HSTS is only meaningful over TLS; browsers ignore it on plain HTTP.
	if isHTTPS(target) && header.Get("Strict-Transport-Security") == "" {
		checks = append(checks, check{target, "missing-hsts", "info", "Strict-Transport-Security header is missing"})
	}

	// X-Frame-Options and CSP frame-ancestors both block framing; either is
	// enough, so a missing XFO is only reported when the CSP directive is
	// absent too.
	if xfo == "" && !strings.Contains(strings.ToLower(csp), "frame-ancestors") {
		checks = append(checks, check{target, "missing-x-frame-options", "info", "X-Frame-Options header is missing"})
	}

	if header.Get("X-Content-Type-Options") == "" {
		checks = append(checks, check{target, "missing-nosniff", "info", "X-Content-Type-Options: nosniff is missing"})
	}

	if header.Get("Referrer-Policy") == "" {
		checks = append(checks, check{target, "missing-referrer-policy", "info", "Referrer-Policy header is missing"})
	}

	if header.Get("Permissions-Policy") == "" {
		checks = append(checks, check{target, "missing-permissions-policy", "info", "Permissions-Policy header is missing"})
	}

	for _, cookie := range header.Values("Set-Cookie") {
		name, secure, httpOnly := cookieFlags(cookie)
		if !secure {
			checks = append(checks, check{target, "cookie-without-secure", "low", fmt.Sprintf("Set-Cookie %q is not marked Secure", name)})
		}
		if !httpOnly {
			checks = append(checks, check{target, "cookie-without-httponly", "low", fmt.Sprintf("Set-Cookie %q is not marked HttpOnly", name)})
		}
	}

	return checks
}

func isHTTPS(target string) bool {
	return strings.HasPrefix(strings.ToLower(target), "https://")
}

// cookieFlags extracts the cookie name and the Secure/HttpOnly attributes by
// parsing the Set-Cookie value instead of substring matching, so that values
// containing the words "secure" or "httponly" cannot fool the checks.
func cookieFlags(cookie string) (name string, secure, httpOnly bool) {
	parts := strings.Split(cookie, ";")
	name = strings.TrimSpace(parts[0])
	if i := strings.IndexByte(name, '='); i > 0 {
		name = name[:i]
	}
	for _, attr := range parts[1:] {
		key := strings.TrimSpace(attr)
		if i := strings.IndexByte(key, '='); i > 0 {
			key = key[:i]
		}
		switch strings.ToLower(key) {
		case "secure":
			secure = true
		case "httponly":
			httpOnly = true
		}
	}
	return name, secure, httpOnly
}

func applyHeaders(req *http.Request, headers []string) {
	for _, header := range headers {
		name, value, ok := strings.Cut(header, ":")
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		if !ok || name == "" {
			continue
		}
		req.Header.Set(name, value)
	}
}

// staticAssetExts are the path suffixes treated as static assets. Header
// hardening is host-level, so URLs serving these are never checked.
var staticAssetExts = []string{
	".js", ".mjs", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
	".webp", ".avif", ".ico", ".woff", ".woff2", ".ttf", ".otf", ".eot",
	".map", ".mp4", ".webm",
}

// isStaticAsset reports whether raw points at a static asset: its path
// (lower-cased, query string ignored) ends with a known asset extension.
// robots.txt, manifest.json and sw.js are not treated as assets.
func isStaticAsset(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	path := strings.ToLower(strings.TrimPrefix(u.Path, "/"))
	switch path {
	case "robots.txt", "manifest.json", "sw.js":
		return false
	}
	for _, ext := range staticAssetExts {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

func readURLs(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = file.Close() }()

	var urls []string
	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || isStaticAsset(line) {
			continue
		}
		if _, dup := seen[line]; dup {
			continue
		}
		seen[line] = struct{}{}
		urls = append(urls, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return urls, nil
}

func writeChecks(path string, checks []check) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("failed to create HTTP checks directory: %w", err)
	}
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create HTTP checks file: %w", err)
	}
	defer func() { _ = file.Close() }()

	encoder := json.NewEncoder(file)
	for _, item := range checks {
		if err := encoder.Encode(item); err != nil {
			return fmt.Errorf("failed to write HTTP checks: %w", err)
		}
	}
	return nil
}
