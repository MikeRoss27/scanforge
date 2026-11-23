package dbdetect

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/modules/dbcore"
	scanScope "github.com/MikeRoss27/scanforge/internal/scope"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

func makeJWT(t *testing.T, claims map[string]string) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString([]byte("signature-not-verified"))
}

func testRun(t *testing.T) *storage.Run {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{"00_meta", "05_content", "06_vulns"} {
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

func TestRunDetectsAndAutoScopes(t *testing.T) {
	serviceJWT := makeJWT(t, map[string]string{"role": "service_role", "iss": "supabase"})
	bundle := `import { createClient } from '@supabase/supabase-js'
const url = 'https://abcdefghijklmnopqrst.supabase.co'
const anon = 'sb_publishable_0123456789abcdefghij_KQ'
// leaked server key in the client bundle:
const admin = '` + serviceJWT + `'
const firebaseConfig = { apiKey: "AIzaSyB1234567890abcdefghijklmnopqrstuv", databaseURL: "https://proj-default-rtdb.firebaseio.com" };
`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(bundle))
	}))
	defer server.Close()

	run := testRun(t)
	writeFile(t, run.Path("05_content", "katana.txt"), server.URL+"/app.js\n")

	host := hostOf(t, server.URL) // 127.0.0.1
	scope, err := scanScope.FromTarget(host, scanScope.ModeExact, nil, nil)
	if err != nil {
		t.Fatalf("build scope: %v", err)
	}
	runCtx := modules.NewRunContext(host, "web", false, run, scope)

	var mu sync.Mutex
	findings := map[string]string{} // title+detail severity by severity key
	bySeverity := map[string]int{}
	runCtx.SetFindingSink(func(f modules.Finding) {
		mu.Lock()
		defer mu.Unlock()
		findings[f.Severity+"|"+f.Title] = f.Detail
		bySeverity[f.Severity]++
	})

	if err := runCtx.AddArtifact("crawled_urls", modules.Artifact{Name: "crawled_urls", Type: "text", Path: "05_content/katana.txt"}); err != nil {
		t.Fatal(err)
	}

	if _, err := New().Run(context.Background(), runCtx, nil); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	// Artifact published.
	if _, ok := runCtx.GetArtifact("db_fingerprint"); !ok {
		t.Fatal("db_fingerprint artifact not published")
	}
	records, err := dbcore.Load(run.Path(outputRel))
	if err != nil {
		t.Fatalf("load fingerprint: %v", err)
	}
	if len(records) == 0 {
		t.Fatal("no fingerprint records written")
	}

	// Supabase host auto-added to the scope as an exact host.
	const supaHost = "abcdefghijklmnopqrst.supabase.co"
	if !scope.IsAllowed(supaHost) {
		t.Errorf("supabase host %q was not added to scope", supaHost)
	}
	// Only the exact host, never a wildcard: a sibling must stay out.
	if scope.IsAllowed("evil." + supaHost) {
		t.Error("auto-scope widened to a wildcard; sibling host should be out of scope")
	}

	// Provenance recorded.
	prov, err := os.ReadFile(run.Path("00_meta", "scope-additions.jsonl"))
	if err != nil {
		t.Fatalf("read provenance: %v", err)
	}
	if !strings.Contains(string(prov), supaHost) || !strings.Contains(string(prov), `"source":"dbdetect"`) {
		t.Errorf("provenance missing host/source: %s", prov)
	}

	// Severities: the service_role key is critical, the publishable anon is info.
	mu.Lock()
	defer mu.Unlock()
	if bySeverity["critical"] == 0 {
		t.Errorf("expected a critical finding for the leaked service_role key; got %v", bySeverity)
	}
	if bySeverity["info"] == 0 {
		t.Errorf("expected an info finding for the public keys; got %v", bySeverity)
	}

	// The critical finding must not leak the full service_role JWT to the log.
	for key, detail := range findings {
		if strings.HasPrefix(key, "critical|") && strings.Contains(detail, serviceJWT) {
			t.Error("critical finding detail leaked the full service_role key")
		}
	}
	// Nor may the on-disk record persist it in full.
	for _, rec := range records {
		if rec.KeyType == "supabase-service-role-jwt" && rec.KeyValue != "" {
			t.Error("service_role key persisted in full on disk")
		}
	}
}

func TestRunDryRunDoesNotProbeOrScope(t *testing.T) {
	run := testRun(t)
	writeFile(t, run.Path("05_content", "katana.txt"), "https://app.example.com/app.js\n")

	scope, err := scanScope.FromTarget("app.example.com", scanScope.ModeExact, nil, nil)
	if err != nil {
		t.Fatalf("build scope: %v", err)
	}
	runCtx := modules.NewRunContext("app.example.com", "web", true, run, scope)
	if err := runCtx.AddArtifact("crawled_urls", modules.Artifact{Name: "crawled_urls", Type: "text", Path: "05_content/katana.txt"}); err != nil {
		t.Fatal(err)
	}

	res, err := New().Run(context.Background(), runCtx, nil)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if res.Status != "completed" {
		t.Fatalf("dry run status = %q", res.Status)
	}
	if _, ok := runCtx.GetArtifact("db_fingerprint"); !ok {
		t.Fatal("db_fingerprint must still be published in a dry run")
	}
	records, _ := dbcore.Load(run.Path(outputRel))
	if len(records) != 0 {
		t.Fatalf("dry run must not fetch or record anything, got %v", records)
	}
	if _, err := os.Stat(run.Path("00_meta", "scope-additions.jsonl")); !os.IsNotExist(err) {
		t.Fatal("dry run must not modify scope / write provenance")
	}
}

func TestDedupeRecords(t *testing.T) {
	in := []dbcore.FingerprintRecord{
		{Backend: "supabase", Host: "ref.supabase.co", KeyType: "supabase-publishable"},
		{Backend: "supabase", Host: "ref.supabase.co", KeyType: "supabase-publishable"}, // dup
		{Backend: "firebase", Host: "a.firebaseio.com"},
		{Backend: "appwrite", Host: "cloud.appwrite.io"},
	}
	out := dedupeRecords(in)
	if len(out) != 3 {
		t.Fatalf("dedupe = %d records, want 3: %+v", len(out), out)
	}
	// Deterministic order: appwrite, firebase, supabase.
	if out[0].Backend != "appwrite" || out[1].Backend != "firebase" || out[2].Backend != "supabase" {
		t.Fatalf("records not sorted deterministically: %+v", out)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}
