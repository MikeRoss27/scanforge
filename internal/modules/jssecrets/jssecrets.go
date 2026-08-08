// Package jssecrets scans crawled JavaScript for exposed secrets, cloud
// buckets, internal hosts, emails and source maps.
package jssecrets

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
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
)

const (
	// workerCount bounds concurrent fetches. JS files are small and the work is
	// network bound, so this can be higher than the process-spawning modules.
	workerCount    = 10
	requestTimeout = 15 * time.Second
	// maxBodyBytes caps each response so a hostile or oversized bundle cannot
	// exhaust memory.
	maxBodyBytes = 5 << 20
	outputRel    = "06_vulns/js-secrets.jsonl"

	kindSecret       = "secret"
	kindCloudStorage = "cloud-storage"
	kindInternalHost = "internal-host"
	kindEmail        = "email"
	kindEndpoint     = "endpoint"
	kindSourceMap    = "source-map"
)

// patternRule is a regex-driven detector. Group selects which submatch to
// report (0 means the whole match, used when the regex has no delimiters to
// strip); Kind categorizes the finding for report routing (secrets and
// PII/exposure findings become Vulnerability entries, endpoints are surfaced
// as discovered paths instead).
type patternRule struct {
	Name     string
	Kind     string
	Severity string
	Regex    *regexp.Regexp
	Group    int
}

var rules = []patternRule{
	// --- credentials & API keys ---
	{"aws-access-key-id", kindSecret, "critical", regexp.MustCompile(`AKIA[0-9A-Z]{16}`), 0},
	{"aws-secret-access-key", kindSecret, "critical", regexp.MustCompile(`(?i)aws(.{0,20})?(secret|access)?(.{0,20})?['"][0-9a-zA-Z/+]{40}['"]`), 0},
	{"private-key-block", kindSecret, "critical", regexp.MustCompile(`-----BEGIN[ A-Z]*PRIVATE KEY-----`), 0},
	{"pgp-private-key-block", kindSecret, "critical", regexp.MustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK-----`), 0},
	{"database-connection-string", kindSecret, "critical", regexp.MustCompile(`(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp):\/\/[^:\/\s'"]+:[^@\/\s'"]+@[^\s'"]+`), 0},
	{"azure-storage-connection-string", kindSecret, "critical", regexp.MustCompile(`DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[^;]+`), 0},
	{"stripe-live-key", kindSecret, "critical", regexp.MustCompile(`[sr]k_live_[0-9a-zA-Z]{20,247}`), 0},
	{"basic-auth-in-url", kindSecret, "high", regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9+.\-]*:\/\/[^\/\s:@'"]{1,64}:[^\/\s:@'"]{1,64}@[^\/\s'"]{3,}`), 0},
	{"github-token", kindSecret, "high", regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,255}`), 0},
	{"slack-token", kindSecret, "high", regexp.MustCompile(`xox[baprs]-[0-9A-Za-z-]{10,48}`), 0},
	{"slack-webhook", kindSecret, "high", regexp.MustCompile(`https://hooks\.slack\.com/services/[A-Za-z0-9+/]{6,56}`), 0},
	{"discord-webhook", kindSecret, "high", regexp.MustCompile(`https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_\-]+`), 0},
	{"telegram-bot-token", kindSecret, "high", regexp.MustCompile(`[0-9]{8,10}:AA[0-9A-Za-z_\-]{33}`), 0},
	{"firebase-cloud-messaging-key", kindSecret, "high", regexp.MustCompile(`AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{100,}`), 0},
	{"mailgun-api-key", kindSecret, "high", regexp.MustCompile(`key-[0-9a-zA-Z]{32}`), 0},
	{"twilio-api-key", kindSecret, "high", regexp.MustCompile(`SK[0-9a-fA-F]{32}`), 0},
	{"npm-access-token", kindSecret, "high", regexp.MustCompile(`npm_[A-Za-z0-9]{36}`), 0},
	{"square-access-token", kindSecret, "high", regexp.MustCompile(`sq0(?:atp|csp)-[0-9A-Za-z\-_]{22,43}`), 0},
	{"heroku-api-key", kindSecret, "high", regexp.MustCompile(`(?i)heroku[a-zA-Z0-9_ \-]{0,20}["'][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}["']`), 0},
	{"google-api-key", kindSecret, "medium", regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`), 0},
	{"google-oauth-client-id", kindSecret, "medium", regexp.MustCompile(`[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`), 0},
	{"sentry-dsn", kindSecret, "medium", regexp.MustCompile(`https:\/\/[0-9a-f]{32}@[0-9a-zA-Z.\-]+\/[0-9]+`), 0},
	{"generic-bearer-token", kindSecret, "medium", regexp.MustCompile(`(?i)bearer\s+[a-zA-Z0-9_\-.=]{20,500}`), 0},
	{"generic-secret-assignment", kindSecret, "medium", regexp.MustCompile(`(?i)(api[_-]?key|apikey|secret|access[_-]?token|auth[_-]?token)["']?\s*[:=]\s*["'][0-9a-zA-Z\-_/+]{16,64}["']`), 0},
	{"jwt", kindSecret, "low", regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`), 0},

	// --- cloud storage buckets (often left publicly readable/writable) ---
	{"aws-s3-bucket", kindCloudStorage, "medium", regexp.MustCompile(`(?:[a-z0-9][a-z0-9.\-]{1,61}\.s3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com|s3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com\/[a-z0-9][a-z0-9.\-]{1,61})`), 0},
	{"gcp-storage-bucket", kindCloudStorage, "medium", regexp.MustCompile(`(?:storage\.googleapis\.com\/[a-zA-Z0-9._\-]+|[a-zA-Z0-9][a-zA-Z0-9._\-]{1,61}\.storage\.googleapis\.com)`), 0},
	{"azure-blob-storage", kindCloudStorage, "medium", regexp.MustCompile(`[a-zA-Z0-9][a-zA-Z0-9\-]{1,61}\.blob\.core\.windows\.net`), 0},
	{"digitalocean-spaces", kindCloudStorage, "medium", regexp.MustCompile(`[a-zA-Z0-9][a-zA-Z0-9\-]{1,61}\.[a-z0-9\-]+\.digitaloceanspaces\.com`), 0},

	// --- internal network exposure ---
	{"internal-ipv4-address", kindInternalHost, "low", regexp.MustCompile(`\b(?:10(?:\.[0-9]{1,3}){3}|172\.(?:1[6-9]|2[0-9]|3[0-1])(?:\.[0-9]{1,3}){2}|192\.168(?:\.[0-9]{1,3}){2})\b`), 0},
	{"internal-hostname", kindInternalHost, "low", regexp.MustCompile(`\b[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.(?:internal|local|corp|intranet|lan)\b`), 0},

	// --- PII ---
	{"email-address", kindEmail, "info", regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`), 0},

	// --- attack surface: API-like paths worth fuzzing further ---
	{"sensitive-api-endpoint", kindEndpoint, "info", regexp.MustCompile(`["'](\/(?:api|internal|admin|graphql|gql|v[0-9]+|auth|oauth2?|debug|config|swagger|openapi|actuator|console|manage|dashboard|backend)(?:\/[a-zA-Z0-9_\-{}.$]+){0,6}\/?)["']`), 1},
}

// placeholderEmailDomains filters out example/test fixtures that show up
// constantly in form-validation code and documentation strings, which would
// otherwise flood findings with noise instead of real addresses.
var placeholderEmailDomains = map[string]struct{}{
	"example.com": {}, "example.org": {}, "example.net": {},
	"test.com": {}, "domain.com": {}, "yourcompany.com": {},
	"company.com": {}, "email.com": {}, "acme.com": {}, "foo.com": {},
	"yourdomain.com": {}, "site.com": {}, "sample.com": {},
}

var sourceMapCommentPattern = regexp.MustCompile(`\/\/[#@]\s*sourceMappingURL=([^\s'"]+)`)

type finding struct {
	URL      string `json:"url"`
	Kind     string `json:"kind"`
	Pattern  string `json:"pattern"`
	Severity string `json:"severity"`
	Match    string `json:"match"`
}

type Module struct{}

func New() *Module {
	return &Module{}
}

func (m *Module) Name() string { return "jssecrets" }
func (m *Module) Description() string {
	return "Fetches crawled JavaScript files and flags exposed secrets, cloud storage buckets, internal hosts, emails, sensitive endpoints, and exposed source maps"
}
func (m *Module) Requires() []string { return []string{"crawled_urls"} }
func (m *Module) Produces() []string { return []string{"js_secrets"} }

func (m *Module) Run(ctx context.Context, runCtx *modules.RunContext, _ runner.Executor) (*modules.Result, error) {
	inputArt, err := runCtx.MustArtifact("crawled_urls")
	if err != nil {
		return nil, err
	}
	inputFile := runCtx.Run.Path(inputArt.Path)

	urls, err := readJSURLs(inputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read crawled URLs: %w", err)
	}

	// No subprocess runs here, but the audit trail should still show what this
	// module did, so a synthetic entry is recorded like every other module.
	if err := runner.AppendCommandLog(runCtx.Run.CommandsLog, runner.Command{
		Name: "jssecrets (native)",
		Args: []string{
			"-input", inputFile,
			"-js-urls", strconv.Itoa(len(urls)),
			"-workers", strconv.Itoa(workerCount),
		},
	}); err != nil {
		return nil, fmt.Errorf("failed to write commands log: %w", err)
	}

	var findings []finding
	if !runCtx.DryRun && len(urls) > 0 {
		findings, err = scanURLs(ctx, runCtx, urls)
		if err != nil {
			return nil, err
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].URL != findings[j].URL {
			return findings[i].URL < findings[j].URL
		}
		if findings[i].Kind != findings[j].Kind {
			return findings[i].Kind < findings[j].Kind
		}
		if findings[i].Pattern != findings[j].Pattern {
			return findings[i].Pattern < findings[j].Pattern
		}
		return findings[i].Match < findings[j].Match
	})

	if err := writeFindings(runCtx.Run.Path("06_vulns", "js-secrets.jsonl"), findings); err != nil {
		return nil, err
	}

	if err := runCtx.AddArtifact("js_secrets", modules.Artifact{
		Name: "js_secrets",
		Type: "jsonl",
		Path: outputRel,
	}); err != nil {
		return nil, fmt.Errorf("failed to publish JS secrets: %w", err)
	}

	return &modules.Result{
		Name:   m.Name(),
		Status: "completed",
		OutputFiles: map[string]string{
			"js_secrets": outputRel,
		},
	}, nil
}

func scanURLs(ctx context.Context, runCtx *modules.RunContext, urls []string) ([]finding, error) {
	client, err := buildClient(runCtx.Proxy)
	if err != nil {
		return nil, err
	}

	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		findings []finding
	)
	sem := make(chan struct{}, workerCount)

	for _, target := range urls {
		wg.Add(1)
		sem <- struct{}{}
		go func(target string) {
			defer wg.Done()
			defer func() { <-sem }()

			// Fetching is best effort: an unreachable or non-200 JS file yields
			// no findings rather than failing the module.
			body, err := fetch(ctx, client, target, runCtx.Headers)
			if err != nil {
				return
			}
			matches := scanBody(target, body)
			if sourceMap := detectSourceMap(ctx, client, target, body, runCtx.Headers); sourceMap != nil {
				matches = append(matches, *sourceMap)
			}
			if len(matches) == 0 {
				return
			}
			mu.Lock()
			findings = append(findings, matches...)
			mu.Unlock()
		}(target)
	}
	wg.Wait()

	return findings, nil
}

func buildClient(proxy string) (*http.Client, error) {
	transport := &http.Transport{}
	if proxy != "" {
		parsed, err := url.Parse(proxy)
		if err != nil {
			return nil, fmt.Errorf("failed to parse proxy %q: %w", proxy, err)
		}
		transport.Proxy = http.ProxyURL(parsed)
	}
	return &http.Client{Timeout: requestTimeout, Transport: transport}, nil
}

func fetch(ctx context.Context, client *http.Client, target string, headers []string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", err
	}
	applyHeaders(req, headers)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d for %q", resp.StatusCode, target)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return "", err
	}
	return string(body), nil
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

func scanBody(target, body string) []finding {
	var results []finding
	for _, rule := range rules {
		seen := make(map[string]struct{})
		for _, groups := range rule.Regex.FindAllStringSubmatch(body, -1) {
			value := groups[0]
			if rule.Group > 0 && rule.Group < len(groups) {
				value = groups[rule.Group]
			}
			if value == "" {
				continue
			}
			if rule.Kind == kindEmail && isPlaceholderEmail(value) {
				continue
			}
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			results = append(results, finding{
				URL:      target,
				Kind:     rule.Kind,
				Pattern:  rule.Name,
				Severity: rule.Severity,
				Match:    value,
			})
		}
	}
	return results
}

func isPlaceholderEmail(address string) bool {
	_, domain, ok := strings.Cut(address, "@")
	if !ok {
		return false
	}
	_, blocked := placeholderEmailDomains[strings.ToLower(domain)]
	return blocked
}

// detectSourceMap looks for a "//# sourceMappingURL=..." comment and, if
// found, resolves it against the JS file's own URL and confirms the map is
// actually reachable before reporting it — the comment alone is a common
// false positive when the .map file was intentionally excluded from
// deployment.
func detectSourceMap(ctx context.Context, client *http.Client, jsURL, body string, headers []string) *finding {
	match := sourceMapCommentPattern.FindStringSubmatch(body)
	if match == nil {
		return nil
	}
	resolved := resolveURL(jsURL, strings.TrimSpace(match[1]))
	if resolved == "" || !verifyReachable(ctx, client, resolved, headers) {
		return nil
	}
	return &finding{
		URL:      jsURL,
		Kind:     kindSourceMap,
		Pattern:  "exposed-source-map",
		Severity: "medium",
		Match:    resolved,
	}
}

func resolveURL(base, ref string) string {
	baseURL, err := url.Parse(base)
	if err != nil {
		return ""
	}
	refURL, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	return baseURL.ResolveReference(refURL).String()
}

func verifyReachable(ctx context.Context, client *http.Client, target string, headers []string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return false
	}
	applyHeaders(req, headers)

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.CopyN(io.Discard, resp.Body, 1)
	return resp.StatusCode == http.StatusOK
}

// readJSURLs returns the deduplicated JavaScript URLs from a katana output
// file. A missing file means the upstream crawl never wrote one (dry runs skip
// execution), which is an empty list rather than an error.
func readJSURLs(path string) ([]string, error) {
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
		if line == "" || !isJavaScriptURL(line) {
			continue
		}
		if _, ok := seen[line]; ok {
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

// isJavaScriptURL inspects the parsed path so query strings (app.js?v=2) still
// match and lookalike extensions (.json, .jsx) do not.
func isJavaScriptURL(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}
	path := strings.ToLower(parsed.Path)
	return strings.HasSuffix(path, ".js") || strings.HasSuffix(path, ".mjs")
}

func writeFindings(path string, findings []finding) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("failed to create JS secrets output directory: %w", err)
	}
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create JS secrets output: %w", err)
	}
	defer func() { _ = file.Close() }()

	encoder := json.NewEncoder(file)
	for _, item := range findings {
		if err := encoder.Encode(item); err != nil {
			return fmt.Errorf("failed to write JS secrets output: %w", err)
		}
	}
	return nil
}
