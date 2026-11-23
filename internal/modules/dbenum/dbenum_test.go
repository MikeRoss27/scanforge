package dbenum

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"net/http"
	"net/http/httptest"
	"net/url"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/modules/dbcore"
	scanScope "github.com/MikeRoss27/scanforge/internal/scope"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

const secretRowMarker = "SUPER_SECRET_ROW_VALUE_DO_NOT_STORE"

func testRun(t *testing.T) *storage.Run {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{"00_meta", "06_vulns"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0755); err != nil {
			t.Fatal(err)
		}
	}
	return &storage.Run{
		RootDir:     root,
		MetaDir:     filepath.Join(root, "00_meta"),
		CommandsLog: filepath.Join(root, "00_meta", "commands.log"),
	}
}

func hostOf(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u.Hostname()
}

// supabaseServer mimics the subset of PostgREST + GoTrue that dbenum probes.
func supabaseServer(t *testing.T, paths *[]string, mu *sync.Mutex) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		*paths = append(*paths, r.URL.Path+"?"+r.URL.RawQuery)
		mu.Unlock()
		switch r.URL.Path {
		case "/rest/v1/":
			if r.Header.Get("apikey") == "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/openapi+json")
			_, _ = w.Write([]byte(`{"swagger":"2.0","definitions":{"public_notes":{},"private_audit":{}},"paths":{"/":{}}}`))
		case "/rest/v1/public_notes":
			// Readable under anon: return a count, and (hostilely) a row body.
			// dbenum must store the count but never the row body.
			w.Header().Set("Content-Range", "0-0/7")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[{"secret":"` + secretRowMarker + `"}]`))
		case "/rest/v1/private_audit":
			// RLS blocks anon reads.
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"message":"permission denied"}`))
		case "/auth/v1/settings":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"external":{"github":true,"email":true},"disable_signup":false}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func writeFingerprint(t *testing.T, run *storage.Run, runCtx *modules.RunContext, recs []dbcore.FingerprintRecord) {
	t.Helper()
	rel := dbcore.OutputDir + "/db-fingerprint.jsonl"
	if err := dbcore.Save(run.Path(rel), recs); err != nil {
		t.Fatalf("save fingerprint: %v", err)
	}
	if err := runCtx.AddArtifact("db_fingerprint", modules.Artifact{Name: "db_fingerprint", Type: "jsonl", Path: rel}); err != nil {
		t.Fatalf("add artifact: %v", err)
	}
}

func TestSupabaseEnumInScopeAndNonExfil(t *testing.T) {
	var (
		mu    sync.Mutex
		paths []string
	)
	server := supabaseServer(t, &paths, &mu)
	defer server.Close()

	run := testRun(t)
	host := hostOf(t, server.URL) // 127.0.0.1
	scope, err := scanScope.FromTarget(host, scanScope.ModeExact, nil, nil)
	if err != nil {
		t.Fatalf("scope: %v", err)
	}
	runCtx := modules.NewRunContext(host, "web", false, run, scope)

	var findMu sync.Mutex
	bySev := map[string]int{}
	readableTables := []string{}
	runCtx.SetFindingSink(func(f modules.Finding) {
		findMu.Lock()
		defer findMu.Unlock()
		bySev[f.Severity]++
		if strings.Contains(f.Title, "readable") {
			readableTables = append(readableTables, f.Detail)
		}
	})

	writeFingerprint(t, run, runCtx, []dbcore.FingerprintRecord{{
		Target:   host,
		Backend:  string(dbcore.Supabase),
		Endpoint: server.URL,
		Host:     host,
		KeyType:  "supabase-anon-jwt",
		KeyValue: "anon-key-123",
	}})

	res, err := New().Run(context.Background(), runCtx, nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Status != "completed" {
		t.Fatalf("status=%q", res.Status)
	}

	// One readable table (high), private table not reported, auth settings (info).
	if bySev["high"] != 1 {
		t.Errorf("expected 1 high finding, got %d", bySev["high"])
	}
	if bySev["info"] < 1 {
		t.Errorf("expected auth-settings info finding, got %d", bySev["info"])
	}
	if len(readableTables) != 1 || !strings.Contains(readableTables[0], "7 rows") {
		t.Errorf("expected count 7 in readable finding, got %v", readableTables)
	}

	// Non-exfiltration: the row body must never reach the audit artifact.
	data, err := os.ReadFile(run.Path(outputRel))
	if err != nil {
		t.Fatalf("read artifact: %v", err)
	}
	if strings.Contains(string(data), secretRowMarker) {
		t.Fatalf("row data leaked into db-enum.jsonl:\n%s", data)
	}
	// The table probe must be count-only (limit=0).
	mu.Lock()
	joined := strings.Join(paths, "\n")
	mu.Unlock()
	if !strings.Contains(joined, "/rest/v1/public_notes?limit=0") {
		t.Fatalf("expected limit=0 count probe, saw:\n%s", joined)
	}
}

func TestOutOfScopeHostIsNeverProbed(t *testing.T) {
	var (
		inMu    sync.Mutex
		inPaths []string
		outHits int32
	)
	inServer := supabaseServer(t, &inPaths, &inMu)
	defer inServer.Close()
	outServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&outHits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer outServer.Close()

	run := testRun(t)
	inHost := hostOf(t, inServer.URL)
	// Scope allows only the in-scope host; the out-of-scope record uses a host
	// name that is deliberately not in scope even though it resolves to the
	// local test server.
	scope, err := scanScope.FromTarget(inHost, scanScope.ModeExact, nil, nil)
	if err != nil {
		t.Fatalf("scope: %v", err)
	}
	runCtx := modules.NewRunContext(inHost, "web", false, run, scope)

	var warnings []string
	var wmu sync.Mutex
	runCtx.SetWarningSink(func(m string) { wmu.Lock(); warnings = append(warnings, m); wmu.Unlock() })

	writeFingerprint(t, run, runCtx, []dbcore.FingerprintRecord{
		{Target: inHost, Backend: string(dbcore.Supabase), Endpoint: inServer.URL, Host: inHost, KeyValue: "anon-key-123"},
		{Target: inHost, Backend: string(dbcore.Supabase), Endpoint: outServer.URL, Host: "evil.supabase.co", KeyValue: "anon-key-xyz"},
	})

	if _, err := New().Run(context.Background(), runCtx, nil); err != nil {
		t.Fatalf("run: %v", err)
	}

	if got := atomic.LoadInt32(&outHits); got != 0 {
		t.Fatalf("out-of-scope host was probed %d times", got)
	}
	inMu.Lock()
	n := len(inPaths)
	inMu.Unlock()
	if n == 0 {
		t.Fatalf("in-scope host should have been probed")
	}
	wmu.Lock()
	defer wmu.Unlock()
	foundWarn := false
	for _, w := range warnings {
		if strings.Contains(w, "evil.supabase.co") && strings.Contains(w, "out of scope") {
			foundWarn = true
		}
	}
	if !foundWarn {
		t.Fatalf("expected an out-of-scope warning, got %v", warnings)
	}
}

func TestDryRunMakesNoNetworkCalls(t *testing.T) {
	var (
		mu    sync.Mutex
		paths []string
	)
	server := supabaseServer(t, &paths, &mu)
	defer server.Close()

	run := testRun(t)
	host := hostOf(t, server.URL)
	scope, _ := scanScope.FromTarget(host, scanScope.ModeExact, nil, nil)
	runCtx := modules.NewRunContext(host, "web", true /* dryRun */, run, scope)

	writeFingerprint(t, run, runCtx, []dbcore.FingerprintRecord{{
		Target: host, Backend: string(dbcore.Supabase), Endpoint: server.URL, Host: host, KeyValue: "anon-key-123",
	}})

	res, err := New().Run(context.Background(), runCtx, nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Status != "completed" {
		t.Fatalf("status=%q", res.Status)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(paths) != 0 {
		t.Fatalf("dry run made network calls: %v", paths)
	}
	// The command log should still record intent.
	cmdLog, err := os.ReadFile(run.CommandsLog)
	if err != nil {
		t.Fatalf("read command log: %v", err)
	}
	if !strings.Contains(string(cmdLog), "dbenum") {
		t.Fatalf("command log missing dbenum intent:\n%s", cmdLog)
	}
}

func TestNothingInScopeSkips(t *testing.T) {
	run := testRun(t)
	scope, _ := scanScope.FromTarget("example.com", scanScope.ModeExact, nil, nil)
	runCtx := modules.NewRunContext("example.com", "web", false, run, scope)

	writeFingerprint(t, run, runCtx, []dbcore.FingerprintRecord{{
		Target: "example.com", Backend: string(dbcore.Supabase), Endpoint: "https://ref.supabase.co", Host: "ref.supabase.co", KeyValue: "anon",
	}})

	res, err := New().Run(context.Background(), runCtx, nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !modules.IsNotApplicable(res) {
		t.Fatalf("expected skipped-not-applicable, got status=%q reason=%q", res.Status, res.Reason)
	}
}
