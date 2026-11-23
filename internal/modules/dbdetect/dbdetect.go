// Package dbdetect passively identifies backend-as-a-service providers
// (Supabase, Firebase, Appwrite, PocketBase) from the target's own crawled
// pages and JavaScript. It never contacts the detected backend: it only reads
// bytes the crawl already fetched, extracts the project endpoint and any
// client key, and records them. Detected backend hosts are added to the run
// scope (with an audit trail) so an opt-in enumeration stage may later probe
// the target's own infrastructure.
package dbdetect

import (
	"bufio"
	"context"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/modules/dbcore"
	"github.com/MikeRoss27/scanforge/internal/runner"
)

const (
	outputRel      = dbcore.OutputDir + "/db-fingerprint.jsonl"
	workerCount    = 10
	requestTimeout = 20 * time.Second
	maxBodyBytes   = 2 << 20 // 2 MiB per page is plenty for an init bundle.
	maxURLs        = 300
)

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Name() string { return "dbdetect" }
func (m *Module) Description() string {
	return "Passively detects backend-as-a-service providers (Supabase, Firebase, Appwrite, PocketBase) and exposed client keys from crawled pages and JavaScript"
}
func (m *Module) Requires() []string     { return []string{"crawled_urls"} }
func (m *Module) SoftRequires() []string { return []string{"alive_urls", "js_secrets"} }
func (m *Module) Produces() []string     { return []string{"db_fingerprint"} }

func (m *Module) Run(ctx context.Context, runCtx *modules.RunContext, _ runner.Executor) (*modules.Result, error) {
	inputArt, err := runCtx.MustArtifact("crawled_urls")
	if err != nil {
		return nil, err
	}
	urls, err := readURLs(runCtx.Run.Path(inputArt.Path))
	if err != nil {
		return nil, fmt.Errorf("failed to read crawled URLs: %w", err)
	}

	// The alive hosts are always worth probing even when the crawl was thin:
	// the backend init code usually lives on the homepage bundle.
	if art, ok := runCtx.GetArtifact("alive_urls"); ok {
		if hosts, herr := modules.ReadAliveHosts(runCtx.Run.Path(art.Path), maxURLs); herr == nil {
			urls = append(hosts, urls...)
		}
	}
	urls = dedupeCap(urls, maxURLs)

	if err := runner.AppendCommandLog(runCtx.Run.CommandsLog, runner.Command{
		Name: "dbdetect (native)",
		Args: []string{"-urls", strconv.Itoa(len(urls)), "-workers", strconv.Itoa(workerCount), "-mode", "passive"},
	}); err != nil {
		return nil, fmt.Errorf("failed to write commands log: %w", err)
	}

	var records []dbcore.FingerprintRecord
	if !runCtx.DryRun {
		records = scanURLs(ctx, runCtx, urls)
		// The js_secrets artifact is a cheap extra corpus: it already holds
		// matched values pulled from every JS file, which may include a
		// backend URL the page body did not inline.
		if art, ok := runCtx.GetArtifact("js_secrets"); ok {
			if body, rerr := os.ReadFile(runCtx.Run.Path(art.Path)); rerr == nil {
				records = append(records, dbcore.Detect("js_secrets", body)...)
			}
		}
	}

	records = dedupeRecords(records)
	stamp := time.Now().UTC().Format(time.RFC3339)
	for i := range records {
		records[i].FetchedAt = stamp
	}

	if err := dbcore.Save(runCtx.Run.Path(outputRel), records); err != nil {
		return nil, fmt.Errorf("failed to write db fingerprint: %w", err)
	}
	if err := runCtx.AddArtifact("db_fingerprint", modules.Artifact{
		Name: "db_fingerprint",
		Type: "jsonl",
		Path: outputRel,
	}); err != nil {
		return nil, fmt.Errorf("failed to publish db_fingerprint: %w", err)
	}

	m.report(runCtx, records)

	res := &modules.Result{
		Name:        m.Name(),
		Status:      "completed",
		OutputFiles: map[string]string{"db_fingerprint": outputRel},
	}
	// Nothing recognizable behind this target's pages is a normal outcome,
	// not a partial run: render it as a single [SKP] line like the other
	// not-applicable modules instead of a bare [OK] with an empty artifact.
	if len(records) == 0 && !runCtx.DryRun {
		return modules.SkipNotApplicable(res, nil, "no known backend detected")
	}
	return res, nil
}

// report emits a finding per record and auto-scopes each distinct backend host
// exactly once.
func (m *Module) report(runCtx *modules.RunContext, records []dbcore.FingerprintRecord) {
	scoped := map[string]bool{}
	for _, rec := range records {
		severity := rec.KeySeverity
		if severity == "" {
			severity = "info"
		}
		title := fmt.Sprintf("%s backend exposed", titleCase(rec.Backend))
		detail := rec.Endpoint
		if rec.KeyType != "" {
			detail = fmt.Sprintf("%s (%s key %s)", rec.Endpoint, rec.KeyType, rec.KeyRedacted)
		}
		runCtx.EmitFinding(modules.Finding{
			Module:   m.Name(),
			Severity: severity,
			Title:    title,
			Target:   rec.Target,
			Detail:   detail,
		})

		if rec.Host == "" || scoped[rec.Host] {
			continue
		}
		scoped[rec.Host] = true
		if runCtx.AllowDiscoveredHost(rec.Host, m.Name(), "discovered "+rec.Backend+" backend in client code") {
			// Neutral note: the scope widening is expected behaviour, not an
			// alarm. EmitWarning is the only live info channel modules have.
			runCtx.EmitWarning(fmt.Sprintf("dbdetect: added %s to run scope (discovered %s backend)", rec.Host, rec.Backend))
		}
	}
}

// scanURLs fetches each URL concurrently and runs the dbcore signatures over
// the body. Fetching is best effort: an unreachable or oversized page yields
// no records rather than failing the module.
func scanURLs(ctx context.Context, runCtx *modules.RunContext, urls []string) []dbcore.FingerprintRecord {
	if len(urls) == 0 {
		return nil
	}
	client, closeConn, err := modules.NewProxyClient(runCtx.Proxy, requestTimeout)
	if err != nil {
		return nil
	}
	defer closeConn()

	var (
		mu      sync.Mutex
		records []dbcore.FingerprintRecord
		wg      sync.WaitGroup
	)
	sem := make(chan struct{}, workerCount)
	for _, target := range urls {
		wg.Add(1)
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			wg.Done()
			wg.Wait()
			return records
		}
		go func(target string) {
			defer wg.Done()
			defer func() { <-sem }()

			_, body, _, berr := modules.WPBody(ctx, client, target, runCtx.Headers, maxBodyBytes)
			if berr != nil || len(body) == 0 {
				return
			}
			found := dbcore.Detect(target, body)
			if len(found) == 0 {
				return
			}
			mu.Lock()
			records = append(records, found...)
			mu.Unlock()
		}(target)
	}
	wg.Wait()
	return records
}

// dedupeRecords collapses records sharing a (backend, host, key-type) and
// returns them in a deterministic order.
func dedupeRecords(records []dbcore.FingerprintRecord) []dbcore.FingerprintRecord {
	seen := map[string]bool{}
	var out []dbcore.FingerprintRecord
	for _, rec := range records {
		key := rec.Backend + "|" + rec.Host + "|" + rec.KeyType
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Backend != out[j].Backend {
			return out[i].Backend < out[j].Backend
		}
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].KeyType < out[j].KeyType
	})
	return out
}

func titleCase(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func dedupeCap(urls []string, cap int) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(urls))
	for _, u := range urls {
		u = strings.TrimSpace(u)
		if u == "" || seen[u] {
			continue
		}
		seen[u] = true
		out = append(out, u)
		if cap > 0 && len(out) >= cap {
			break
		}
	}
	return out
}

// readURLs reads the crawled_urls artifact (one URL per line), keeping only
// http(s) URLs.
func readURLs(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = file.Close() }()

	var out []string
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if parsed, err := url.Parse(line); err == nil {
			scheme := strings.ToLower(parsed.Scheme)
			if scheme == "http" || scheme == "https" {
				out = append(out, line)
			}
		}
	}
	return out, scanner.Err()
}
