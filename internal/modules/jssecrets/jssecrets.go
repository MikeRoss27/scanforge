// Package jssecrets scans crawled JavaScript for exposed secrets, cloud
// buckets, internal hosts, emails and source maps.
package jssecrets

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
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
	// chaseBudget bounds how many dynamically imported JS chunks are followed
	// beyond the initial crawl, so lazy-loaded bundles cannot explode the run.
	chaseBudget = 100
	// entropyThreshold is the minimum Shannon entropy per character (base64
	// and hex material typically sits well above 4.5) for a value assigned to
	// a credential-like key to be reported as a generic secret.
	entropyThreshold = 4.5
	outputRel        = "06_vulns/js-secrets.jsonl"
	payloadsRel      = "06_vulns/js-payloads.txt"

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
	// AKIA = long-term IAM user key, ASIA = temporary STS credentials,
	// ABIA = AWS Backup service key, ACCA = AWS CodeCommit key. Most
	// scanners only check AKIA and miss the other three, which are just as
	// usable by an attacker.
	{"aws-access-key-id", kindSecret, "critical", regexp.MustCompile(`(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}`), 0},
	{"aws-secret-access-key", kindSecret, "critical", regexp.MustCompile(`(?i)aws(.{0,20})?(secret|access)?(.{0,20})?['"][0-9a-zA-Z/+]{40}['"]`), 0},
	// STS session tokens are long enough (~270-380 chars, base64-ish) that
	// the length threshold alone keeps false positives out.
	{"aws-session-token", kindSecret, "critical", regexp.MustCompile(`(?i)(?:x-amz-security-token|sessiontoken|session_token)["']?\s*[:=]\s*["'][A-Za-z0-9/+=]{200,}["']`), 0},
	{"cloudinary-url", kindSecret, "critical", regexp.MustCompile(`cloudinary://[0-9]+:[A-Za-z0-9_\-]+@[a-z0-9\-]+`), 0},
	{"postman-api-key", kindSecret, "high", regexp.MustCompile(`PMAK-[0-9a-f]{24}-[0-9a-f]{34}`), 0},
	{"basic-auth-header", kindSecret, "high", regexp.MustCompile(`(?i)authorization["']?\s*:\s*["']Basic\s+[A-Za-z0-9+/]{10,}={0,2}["']`), 0},
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
	{"generic-secret-assignment", kindSecret, "medium", regexp.MustCompile(`(?i)(api[_-]?key|apikey|secret|access[_-]?token|auth[_-]?token|password|passwd|pwd)["']?\s*[:=]\s*["'][0-9a-zA-Z\-_/+]{16,64}["']`), 0},
	{"jwt", kindSecret, "low", regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`), 0},

	// --- cloud provider credentials beyond AWS ---
	{"gcp-service-account-key", kindSecret, "high", regexp.MustCompile(`"private_key_id"\s*:\s*"[0-9a-f]{40}"`), 0},
	{"azure-sas-token", kindSecret, "high", regexp.MustCompile(`\bsig=[A-Za-z0-9%._\-]{8,}(&|["'\s]|$)`), 0},
	{"digitalocean-pat", kindSecret, "high", regexp.MustCompile(`dop_v1_[0-9a-f]{64}`), 0},

	// --- SaaS / service tokens ---
	{"gitlab-ci-token", kindSecret, "high", regexp.MustCompile(`glpat-[A-Za-z0-9_\-]{20,}`), 0},
	{"sendgrid-api-key", kindSecret, "high", regexp.MustCompile(`SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}`), 0},
	{"shopify-access-token", kindSecret, "high", regexp.MustCompile(`shpat_[0-9a-fA-F]{32}`), 0},
	{"grafana-api-key", kindSecret, "high", regexp.MustCompile(`eyJrIjoi[A-Za-z0-9_\-]+`), 0},
	{"huggingface-token", kindSecret, "high", regexp.MustCompile(`hf_[A-Za-z0-9]{34}`), 0},
	// OpenAI project/service-account/admin keys use a hyphen before the
	// subtype, not an underscore (sk-proj-..., not sk-proj_...); the
	// previous pattern used the wrong separator and mixed in several
	// prefixes ("ant", "convo", "instructor", "medium") that belong to
	// other providers or were never real OpenAI prefixes, so it matched
	// almost nothing real. Legacy (pre-2024) keys carry no subtype prefix
	// at all, but reliably encode the base64 string "OpenAI" mid-key
	// (T3BlbkFJ), which is checked separately below.
	{"openai-api-key", kindSecret, "high", regexp.MustCompile(`sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{20,}`), 0},
	{"openai-api-key-legacy", kindSecret, "high", regexp.MustCompile(`sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}`), 0},
	{"anthropic-api-key", kindSecret, "high", regexp.MustCompile(`sk-ant-(?:api03|admin01)-[A-Za-z0-9_\-]{20,}`), 0},
	{"xai-api-key", kindSecret, "high", regexp.MustCompile(`xai-[A-Za-z0-9]{32,}`), 0},
	{"groq-api-key", kindSecret, "high", regexp.MustCompile(`gsk_[A-Za-z0-9]{32,}`), 0},
	{"openrouter-api-key", kindSecret, "high", regexp.MustCompile(`sk-or-v1-[a-f0-9]{64}`), 0},
	{"perplexity-api-key", kindSecret, "high", regexp.MustCompile(`pplx-[A-Za-z0-9]{32,}`), 0},
	{"microsoft-teams-webhook", kindSecret, "high", regexp.MustCompile(`https:\/\/[a-zA-Z0-9.\-]+\.webhook\.office\.com\/webhookb2\/[A-Za-z0-9@\-]+`), 0},

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

// jwtPublicAudiences are aud claim values of well-known public JWTs that ship
// inside every integration of a service and therefore expose nothing. TMDB's
// public API key is embedded in its client JS as the aud claim of a signed
// demo JWT.
var jwtPublicAudiences = map[string]struct{}{
	"584e0eaade05080438692243b4ae069d": {},
}

var sourceMapCommentPattern = regexp.MustCompile(`\/\/[#@]\s*sourceMappingURL=([^\s'"]+)`)

// entropyAssignment captures key = "value" assignments whose value does not
// match any provider-specific rule but may still be a high-entropy secret.
var entropyAssignment = regexp.MustCompile(`["']?([A-Za-z0-9_\-]{3,32})["']?\s*[:=]\s*["']([^"'=]{16,256})["']`)

// entropyKeyHints narrows entropy detection to values assigned to
// credential-like keys, which keeps false positives out of minified bundles.
var entropyKeyHints = []string{"key", "secret", "token", "password", "pass", "auth", "cred", "access"}

// importPatterns finds lazily loaded JavaScript chunks (dynamic import and
// import.meta.url URL construction) worth chasing into.
var importPatterns = []*regexp.Regexp{
	regexp.MustCompile(`import\s*\(\s*["']([^"']+\.(?:js|mjs)(?:\?[^"']*)?)["']`),
	regexp.MustCompile(`new\s+URL\s*\(\s*["']([^"']+\.(?:js|mjs)(?:\?[^"']*)?)["']\s*,\s*import\.meta\.url`),
}

type finding struct {
	URL      string `json:"url"`
	Kind     string `json:"kind"`
	Pattern  string `json:"pattern"`
	Severity string `json:"severity"`
	Match    string `json:"match"`
	// Line, Snippet and Payloads are populated by AST-based analysis findings.
	Line     int      `json:"line,omitempty"`
	Snippet  string   `json:"snippet,omitempty"`
	Payloads []string `json:"payloads,omitempty"`
}

// jsFindingTitle renders a short human-readable label for a live finding
// event; mirrors the titles the report engine assigns the same kinds when it
// builds the final report from js-secrets.jsonl.
func jsFindingTitle(kind, pattern string) string {
	switch kind {
	case kindCloudStorage:
		return "Cloud storage bucket referenced in JavaScript: " + pattern
	case kindInternalHost:
		return "Internal host/IP referenced in JavaScript"
	case kindEmail:
		return "Email address exposed in JavaScript"
	case kindSourceMap:
		return "Source map exposed (leaks original source code)"
	case kindDOMSink:
		return "DOM XSS sink in JavaScript: " + pattern
	case kindNodeSink:
		return "Server-side Node.js API in JavaScript: " + pattern
	case kindProtoPollution:
		return "Prototype pollution vector in JavaScript: " + pattern
	case kindPostMessage:
		return "Unvalidated postMessage usage in JavaScript: " + pattern
	case kindEnvLeak:
		return "Environment variable access in JavaScript: " + pattern
	default:
		return "Exposed secret in JavaScript: " + pattern
	}
}

type Module struct{}

func New() *Module {
	return &Module{}
}

func (m *Module) Name() string { return "jssecrets" }
func (m *Module) Description() string {
	return "Fetches crawled JavaScript files and flags exposed secrets, cloud storage buckets, internal hosts, emails, sensitive endpoints, exposed source maps, and dangerous code patterns (DOM XSS sinks, Node APIs, prototype pollution, unvalidated postMessage) with ready-to-use PoC payloads"
}
func (m *Module) Requires() []string { return []string{"crawled_urls"} }
func (m *Module) Produces() []string { return []string{"js_secrets", "js_payloads"} }

// SoftRequires waits for gau and ffuf, when they're part of the profile, so
// their URL corpora (historical_urls, discovered_paths) are available to
// widen the JS file search beyond what katana's crawl reached. See
// collectJSURLs.
func (m *Module) SoftRequires() []string { return []string{"historical_urls", "discovered_paths"} }

func (m *Module) Run(ctx context.Context, runCtx *modules.RunContext, _ runner.Executor) (*modules.Result, error) {
	inputArt, focus, err := runCtx.FocusedInput("crawled_urls")
	if err != nil {
		return nil, err
	}
	inputFile := runCtx.Run.Path(inputArt.Path)

	urls, crawled, err := collectJSURLs(runCtx, inputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read crawled URLs: %w", err)
	}

	if len(urls) == 0 && !runCtx.DryRun && focus.Empty() {
		// Incremental run: nothing crawled is new or changed, so zero JS
		// files is expected and not a scope-filtering symptom.
		runCtx.EmitWarning("jssecrets: " + focus.SkipReason())
	} else if len(urls) == 0 && !runCtx.DryRun {
		// A real site with zero in-scope JS files is usually a scope-filtering
		// artifact (assets on CDNs/subdomains) rather than a JS-less site.
		// Surface it loudly instead of silently completing the stage.
		runCtx.EmitWarning(fmt.Sprintf(
			"jssecrets: 0 JS files to analyze (crawled_urls has %d line(s) rejected by scope; JS is usually served from subdomains/CDNs — re-run with --scope-mode domain if that applies)",
			runCtx.RejectedCount("crawled_urls"),
		))
	} else if len(urls) > crawled {
		runCtx.EmitWarning(fmt.Sprintf(
			"jssecrets: %d JS file(s) found via gau/ffuf that katana's crawl missed (%d from the crawl, %d total)",
			len(urls)-crawled, crawled, len(urls),
		))
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
	var attempted, fetched, hardFailed int
	if !runCtx.DryRun && len(urls) > 0 {
		findings, attempted, fetched, hardFailed, err = scanURLs(ctx, runCtx, urls)
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

	payloads := collectPayloads(findings)
	if err := writePayloadsFile(runCtx.Run.Path("06_vulns", "js-payloads.txt"), payloads); err != nil {
		return nil, fmt.Errorf("failed to write JS payloads: %w", err)
	}
	if err := runCtx.AddArtifact("js_payloads", modules.Artifact{
		Name: "js_payloads",
		Type: "text",
		Path: payloadsRel,
	}); err != nil {
		return nil, fmt.Errorf("failed to publish JS payloads: %w", err)
	}

	status := "completed"
	var reason string
	if attempted > 0 && fetched == 0 && hardFailed == 0 {
		// Every candidate was a 404/redirect/HTML catch-all: the guessed
		// files simply do not exist, which is not a module failure.
		reason = fmt.Sprintf("none of the %d candidate JS URL(s) served JavaScript (404, redirect or HTML catch-all)", attempted)
	} else if attempted > 0 && fetched == 0 {
		// Every JS file failed to fetch: zero secrets found here means
		// nothing was actually scanned, not that the bundle was clean. A
		// WAF/rate-limit blocking every request is the common cause.
		status = "partial"
		reason = fmt.Sprintf("all %d JS file(s) failed to fetch (%d network error/blocked; proxy issue or WAF?)", attempted, hardFailed)
	}

	return &modules.Result{
		Name:   m.Name(),
		Status: status,
		Reason: reason,
		OutputFiles: map[string]string{
			"js_secrets":  outputRel,
			"js_payloads": payloadsRel,
		},
	}, nil
}

// scanURLs fetches each JS URL and scans it, then follows dynamically imported
// chunks (bounded by chaseBudget) so secrets in lazy-loaded bundles are still
// found. Fetching is best effort: an unreachable or non-200 JS file yields no
// findings rather than failing the module.
// scanURLs fetches each URL and runs the detectors over its body. It returns
// the findings plus how many fetches were attempted and how many actually
// succeeded, so the caller can tell "nothing to find" apart from "every
// request failed".
func scanURLs(ctx context.Context, runCtx *modules.RunContext, urls []string) ([]finding, int, int, int, error) {
	client, err := buildClient(runCtx.Proxy, runCtx.IsInScope)
	if err != nil {
		return nil, 0, 0, 0, err
	}
	defer closeClient(client)

	queue := make([]string, 0, len(urls))
	visited := make(map[string]struct{}, len(urls))
	for _, target := range urls {
		if _, ok := visited[target]; ok {
			continue
		}
		visited[target] = struct{}{}
		queue = append(queue, target)
	}

	var (
		mu                             sync.Mutex
		findings                       []finding
		chased                         int
		attempted, fetched, hardFailed int
		failSamples                    []string
	)

	for len(queue) > 0 {
		batch := queue
		if len(batch) > workerCount*4 {
			batch = queue[:workerCount*4]
		}
		queue = queue[len(batch):]

		var wg sync.WaitGroup
		sem := make(chan struct{}, workerCount)
		var batchMu sync.Mutex
		var next []string

		for _, target := range batch {
			wg.Add(1)
			sem <- struct{}{}
			go func(target string) {
				defer wg.Done()
				defer func() { <-sem }()

				mu.Lock()
				attempted++
				mu.Unlock()

				body, err := fetch(ctx, client, target, runCtx.Headers)
				if err != nil {
					var fe *fetchStatusError
					if errors.As(err, &fe) && fe.isHardFailure() {
						mu.Lock()
						hardFailed++
						if len(failSamples) < 3 {
							failSamples = append(failSamples, fmt.Sprintf("%s (%s)", target, fe))
						}
						mu.Unlock()
					}
					return
				}
				mu.Lock()
				fetched++
				mu.Unlock()

				matches := scanBody(target, body)
				matches = append(matches, scanAST(target, body)...)
				matches = append(matches, scanSourceMaps(ctx, runCtx, client, target, body, runCtx.Headers)...)

				if len(matches) > 0 {
					mu.Lock()
					findings = append(findings, matches...)
					mu.Unlock()

					for _, match := range matches {
						// Endpoints feed the attack surface (discovered_paths
						// downstream), not the vulnerability list, so they're
						// not reported as live findings either.
						if match.Kind == kindEndpoint {
							continue
						}
						runCtx.EmitFinding(modules.Finding{
							Module:   "jssecrets",
							Severity: match.Severity,
							Title:    jsFindingTitle(match.Kind, match.Pattern),
							Target:   match.URL,
							Detail:   match.Match,
						})
					}
				}

				for _, candidate := range chaseImports(target, body) {
					batchMu.Lock()
					if _, seen := visited[candidate]; seen || !runCtx.IsInScope(candidate) || chased >= chaseBudget {
						batchMu.Unlock()
						continue
					}
					visited[candidate] = struct{}{}
					chased++
					next = append(next, candidate)
					batchMu.Unlock()
				}
			}(target)
		}
		wg.Wait()
		queue = append(queue, next...)
	}

	if hardFailed > 0 && fetched == 0 {
		runCtx.EmitWarning(fmt.Sprintf("jssecrets: %d/%d JS fetch(es) blocked or unreachable, e.g. %s",
			hardFailed, attempted, strings.Join(failSamples, "; ")))
	}
	return findings, attempted, fetched, hardFailed, nil
}

// chaseImports extracts absolute URLs of lazily loaded JS chunks referenced by
// a fetched bundle.
func chaseImports(baseURL, body string) []string {
	var candidates []string
	for _, pattern := range importPatterns {
		for _, match := range pattern.FindAllStringSubmatch(body, -1) {
			resolved := resolveURL(baseURL, match[1])
			if resolved != "" && isJavaScriptURL(resolved) && strings.HasPrefix(resolved, "http") {
				candidates = append(candidates, resolved)
			}
		}
	}
	return candidates
}

func buildClient(proxy string, inScope func(string) bool) (*http.Client, error) {
	transport := &http.Transport{}
	if proxy != "" {
		parsed, err := url.Parse(proxy)
		if err != nil {
			return nil, fmt.Errorf("failed to parse proxy %q: %w", proxy, err)
		}
		transport.Proxy = http.ProxyURL(parsed)
	}
	return &http.Client{
		Timeout:   requestTimeout,
		Transport: transport,
		// A redirect is a new request to a host the scope never vetted
		// (CDN, SSO, third-party): refuse to leave scope, like every other
		// fetch in the pipeline.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			if inScope != nil && !inScope(req.URL.String()) {
				return fmt.Errorf("redirect to out-of-scope URL %q refused", req.URL.String())
			}
			return nil
		},
	}, nil
}

// closeClient releases the transport's idle keep-alive connections. Called
// after a scanning session so never-shared sockets are not left lingering.
func closeClient(client *http.Client) {
	if client != nil && client.Transport != nil {
		if t, ok := client.Transport.(*http.Transport); ok {
			t.CloseIdleConnections()
		}
	}
}

// fetchStatusError records why a fetch yielded no JavaScript. Status 0 means
// a transport failure (DNS, TLS, timeout, refused redirect); otherwise it is
// the HTTP status, or 200 with Reason set when the body was not JavaScript.
type fetchStatusError struct {
	Status int
	Reason string
}

func (e *fetchStatusError) Error() string {
	if e.Reason != "" {
		return e.Reason
	}
	return fmt.Sprintf("HTTP %d", e.Status)
}

// isHardFailure reports whether the failure suggests the file may exist but
// was unreachable (network error, auth/WAF block, rate limit, server error).
// A plain 404/410 or an HTML catch-all just means the guessed URL is not a
// real JS file, which is not a module failure.
func (e *fetchStatusError) isHardFailure() bool {
	switch {
	case e.Status == 0, e.Status == 401, e.Status == 403, e.Status == 429, e.Status >= 500:
		return true
	}
	return false
}

func fetch(ctx context.Context, client *http.Client, target string, headers []string) (string, error) {
	body, status, err := fetchBodyStatus(ctx, client, target, headers)
	if err != nil {
		return "", err
	}
	if looksLikeHTML(body) {
		// SPA catch-alls and soft-404 pages answer 200 for any path, even
		// *.js; scanning that HTML as a bundle yields bogus findings.
		return "", &fetchStatusError{Status: status, Reason: "200 but HTML, not JavaScript"}
	}
	return body, nil
}

// looksLikeHTML reports whether body starts like an HTML document.
func looksLikeHTML(body string) bool {
	head := strings.ToLower(strings.TrimSpace(body))
	if len(head) > 256 {
		head = head[:256]
	}
	return strings.HasPrefix(head, "<!doctype html") || strings.HasPrefix(head, "<html") || strings.HasPrefix(head, "<head") || strings.HasPrefix(head, "<body")
}

// fetchBody GETs target and returns the body plus whether the request
// succeeded with a 200 response.
func fetchBody(ctx context.Context, client *http.Client, target string, headers []string) (string, bool) {
	body, _, err := fetchBodyStatus(ctx, client, target, headers)
	return body, err == nil
}

// fetchBodyStatus is fetchBody with the failure cause preserved as a
// *fetchStatusError, so callers can tell a blocked request from a 404.
func fetchBodyStatus(ctx context.Context, client *http.Client, target string, headers []string) (string, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", 0, &fetchStatusError{Reason: err.Error()}
	}
	applyHeaders(req, headers)

	resp, err := client.Do(req)
	if err != nil {
		return "", 0, &fetchStatusError{Reason: err.Error()}
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", resp.StatusCode, &fetchStatusError{Status: resp.StatusCode}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return "", 0, &fetchStatusError{Reason: err.Error()}
	}
	return string(body), resp.StatusCode, nil
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
	reported := make(map[string]struct{})
	for _, rule := range rules {
		seen := make(map[string]struct{})
		for _, loc := range rule.Regex.FindAllStringSubmatchIndex(body, -1) {
			start, end := loc[0], loc[1]
			if rule.Group > 0 && rule.Group*2+1 < len(loc) {
				start, end = loc[rule.Group*2], loc[rule.Group*2+1]
			}
			if start < 0 {
				continue
			}
			value := body[start:end]
			if value == "" {
				continue
			}
			if rule.Kind == kindEmail {
				if isPlaceholderEmail(value) || !hasEmailBoundaries(body, start, end) {
					continue
				}
			}
			if rule.Kind == kindInternalHost && isInternalHostPropertyAccess(body, start, value) {
				continue
			}
			if rule.Name == "jwt" && isPublicJWT(value) {
				continue
			}
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			reported[value] = struct{}{}
			results = append(results, finding{
				URL:      target,
				Kind:     rule.Kind,
				Pattern:  rule.Name,
				Severity: rule.Severity,
				Match:    value,
			})
		}
	}
	results = append(results, scanEntropySecrets(target, body, reported)...)
	return results
}

// isInternalHostPropertyAccess reports whether an internal-host match is
// really a JavaScript property access in a minified bundle rather than a
// reference to an internal host. Minified code reads properties as
// e.internal, this.internal or via longer chains (config.env.internal), all
// of which look like internal hostnames; real references are quoted
// ("payments.internal") or slash-delimited (https://payments.internal/...). A
// match counts as property access when it follows a dot (the tail of a longer
// chain), or — for plain two-segment hostnames — when its label is the this
// or self keyword or a short (1-2 char) minified identifier. IPv4-shaped
// matches never qualify.
func isInternalHostPropertyAccess(body string, start int, match string) bool {
	if start > 0 && body[start-1] == '.' {
		return true
	}
	if strings.Count(match, ".") != 1 {
		return false
	}
	label, _, ok := strings.Cut(match, ".")
	if !ok {
		return false
	}
	return len(label) <= 2 || label == "this" || label == "self"
}

// isPublicJWT reports whether a JWT-shaped match is one of the well-known
// public tokens whose aud claim is whitelisted in jwtPublicAudiences. Tokens
// whose payload cannot be decoded are kept (fail-open) rather than silently
// dropped.
func isPublicJWT(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	var claims struct {
		Aud string `json:"aud"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return false
	}
	_, ok := jwtPublicAudiences[claims.Aud]
	return ok
}

// scanEntropySecrets flags high-entropy values assigned to credential-like
// keys that no provider-specific rule matched. This catches freshly minted or
// less common token formats (gitleaks-style heuristic detection).
func scanEntropySecrets(target, body string, reported map[string]struct{}) []finding {
	var results []finding
	for _, groups := range entropyAssignment.FindAllStringSubmatch(body, -1) {
		key, value := groups[1], groups[2]
		if !hasEntropyHint(key) || len(value) < 16 {
			continue
		}
		if _, ok := reported[value]; ok {
			continue
		}
		// URLs and emails carry enough punctuation that their entropy is
		// meaningless; only flag opaque token-looking values.
		if strings.Contains(value, ".") {
			continue
		}
		if shannonEntropy(value) < entropyThreshold {
			continue
		}
		reported[value] = struct{}{}
		results = append(results, finding{
			URL:      target,
			Kind:     kindSecret,
			Pattern:  "high-entropy-secret",
			Severity: "medium",
			Match:    value,
		})
	}
	return results
}

func hasEntropyHint(key string) bool {
	lower := strings.ToLower(key)
	for _, hint := range entropyKeyHints {
		if strings.Contains(lower, hint) {
			return true
		}
	}
	return false
}

// shannonEntropy returns the per-character Shannon entropy of s, a standard
// heuristic for identifying random-looking secret material.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	freq := make(map[rune]int, len(s))
	for _, r := range s {
		freq[r]++
	}
	var entropy float64
	for _, count := range freq {
		p := float64(count) / float64(len(s))
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func isPlaceholderEmail(address string) bool {
	_, domain, ok := strings.Cut(address, "@")
	if !ok {
		return false
	}
	_, blocked := placeholderEmailDomains[strings.ToLower(domain)]
	return blocked
}

// emailBoundaries are the characters that normally surround an email address
// in source: string delimiters, prose punctuation, JSON/URL separators and
// whitespace. Minified bundles also carry long binary/base64-like blobs where
// an email-shaped substring sits between arbitrary symbols (for example
// "Pp Rfe@Rm.Rs#T2O}..."): those are not addresses and must not be reported.
const emailBoundaries = " \t\r\n\"'`<>,;:()[]{}=/?&\\|"

// hasEmailBoundaries verifies that the match is delimited like a real address
// rather than embedded in a minified token.
func hasEmailBoundaries(body string, start, end int) bool {
	if start > 0 && strings.IndexByte(emailBoundaries, body[start-1]) < 0 {
		return false
	}
	if end < len(body) && strings.IndexByte(emailBoundaries, body[end]) < 0 {
		return false
	}
	return true
}

// scanSourceMaps looks for a "//# sourceMappingURL=..." comment and, if found,
// resolves it against the JS file's own URL and confirms the map is actually
// reachable before reporting it — the comment alone is a common false positive
// when the .map file was intentionally excluded from deployment. Reachable
// maps are parsed so their embedded original sources (sourcesContent) are
// scanned too: original TypeScript/coffee sources often contain the secrets
// that the minifier stripped out. Maps pointing outside the configured scope
// are rejected: fetching them would already have left the target.
func scanSourceMaps(ctx context.Context, runCtx *modules.RunContext, client *http.Client, jsURL, body string, headers []string) []finding {
	match := sourceMapCommentPattern.FindStringSubmatch(body)
	if match == nil {
		return nil
	}
	resolved := resolveURL(jsURL, strings.TrimSpace(match[1]))
	if resolved == "" || !runCtx.IsInScope(resolved) {
		return nil
	}
	content, ok := fetchBody(ctx, client, resolved, headers)
	if !ok {
		return nil
	}
	findings := []finding{{
		URL:      jsURL,
		Kind:     kindSourceMap,
		Pattern:  "exposed-source-map",
		Severity: "medium",
		Match:    resolved,
	}}

	var sourceMap struct {
		SourcesContent []string `json:"sourcesContent"`
	}
	if json.Unmarshal([]byte(content), &sourceMap) == nil {
		for _, source := range sourceMap.SourcesContent {
			if strings.TrimSpace(source) == "" {
				continue
			}
			findings = append(findings, scanBody(resolved, source)...)
			findings = append(findings, scanAST(resolved, source)...)
		}
	}
	return findings
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

// readJSURLs returns the deduplicated JavaScript URLs from a katana output
// file. A missing file means the upstream crawl never wrote one (dry runs skip
// execution), which is an empty list rather than an error.
// collectJSURLs gathers candidate JavaScript file URLs from every corpus
// available, not just the crawl: katana's depth-limited crawl routinely
// misses bundles that are never linked from an HTML <script> tag within its
// depth (lazy-loaded chunks, assets only referenced from old/removed pages),
// which gau's historical URLs (Wayback/CommonCrawl) and ffuf's fuzzed paths
// often still surface. crawled is the count sourced from the crawl alone, so
// the caller can tell "nothing anywhere" apart from "the crawl missed some".
func collectJSURLs(runCtx *modules.RunContext, crawledPath string) (urls []string, crawled int, err error) {
	urls, err = readJSURLs(crawledPath)
	if err != nil {
		return nil, 0, err
	}
	crawled = len(urls)

	seen := make(map[string]struct{}, len(urls))
	for _, u := range urls {
		seen[u] = struct{}{}
	}
	add := func(candidate string) {
		if candidate == "" || !isJavaScriptURL(candidate) || !runCtx.IsInScope(candidate) {
			return
		}
		if _, dup := seen[candidate]; dup {
			return
		}
		seen[candidate] = struct{}{}
		urls = append(urls, candidate)
	}

	if art, ok := runCtx.GetArtifact("historical_urls"); ok {
		if lines, rerr := readLines(runCtx.Run.Path(art.Path)); rerr == nil {
			for _, line := range lines {
				add(line)
			}
		}
	}
	if art, ok := runCtx.GetArtifact("discovered_paths"); ok {
		if ffufURLs, rerr := readFfufURLs(runCtx.Run.Path(art.Path)); rerr == nil {
			for _, u := range ffufURLs {
				add(u)
			}
		}
	}
	return urls, crawled, nil
}

// readLines reads one value per non-empty line; a missing file yields no
// lines rather than an error, matching readJSURLs' tolerance for an absent
// optional corpus.
func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = file.Close() }()

	var lines []string
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		if line := strings.TrimSpace(scanner.Text()); line != "" {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

// readFfufURLs extracts the URL of every ffuf result, mirroring the subset
// of ffuf's JSON schema the report engine's ParseFfuf already relies on.
func readFfufURLs(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var doc struct {
		Results []struct {
			URL    string `json:"url"`
			Status int    `json:"status"`
		} `json:"results"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	urls := make([]string, 0, len(doc.Results))
	for _, r := range doc.Results {
		// Only 2xx responses serve content. Redirects (catch-all 302s on
		// mail/autodiscover hosts) and 403s are fuzzing noise, not JS files.
		if r.Status < 200 || r.Status >= 300 {
			continue
		}
		urls = append(urls, r.URL)
	}
	return urls, nil
}

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
