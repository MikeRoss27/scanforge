package wpxmlrpc

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/modules/wpcore"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

const listMethodsReply = `<?xml version="1.0"?>
<methodResponse>
  <params>
    <param>
      <value>
        <array>
          <data>
            <member><value><string>system.multicall</string></value></member>
            <member><value><string>system.listMethods</string></value></member>
            <member><value><string>pingback.ping</string></value></member>
            <member><value><string>wp.getUsersBlogs</string></value></member>
          </data>
        </array>
      </value>
    </param>
  </params>
</methodResponse>`

func TestProbeXMLRPCEnabled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/xmlrpc.php" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/xml")
		_, _ = io.WriteString(w, listMethodsReply)
	}))
	defer server.Close()

	runCtx := testRunContext(t)
	host := wpcore.FingerprintRecord{Target: server.URL, IsWordPress: true, CoreVersion: "6.4.2", FetchedAt: time.Now().UTC().Format(time.RFC3339)}
	finding := probeXMLRPC(context.Background(), server.Client(), runCtx, host)
	if !finding.Enabled {
		t.Fatal("expected XML-RPC to be detected as enabled")
	}
	if !finding.HasMulticall {
		t.Fatal("expected multicall detection")
	}
	if !finding.Pingback {
		t.Fatal("expected pingback detection")
	}
	if len(finding.Methods) != 4 {
		t.Fatalf("methods = %v, want 4 methods", finding.Methods)
	}
}

func TestProbeXMLRPCNotXMLRPC(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "plain 404-like page")
	}))
	defer server.Close()

	runCtx := testRunContext(t)
	host := wpcore.FingerprintRecord{Target: server.URL, IsWordPress: true, CoreVersion: "6.4.2", FetchedAt: time.Now().UTC().Format(time.RFC3339)}
	finding := probeXMLRPC(context.Background(), server.Client(), runCtx, host)
	if finding.Enabled {
		t.Fatalf("expected XML-RPC to be disabled, got %+v", finding)
	}
}

func TestProbeXMLRPCForbiddenTreatedAsBlocked(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	runCtx := testRunContext(t)
	host := wpcore.FingerprintRecord{Target: server.URL, IsWordPress: true}
	finding := probeXMLRPC(context.Background(), server.Client(), runCtx, host)
	if finding.Enabled {
		t.Fatalf("a 403 must be reported as blocked, not enabled: %+v", finding)
	}
	if finding.Evidence != "HTTP 403" {
		t.Fatalf("evidence = %q, want it to note the blocking status", finding.Evidence)
	}
}

func TestProbeXMLRPCGetFallbackDetectsEnabled(t *testing.T) {
	// WordPress's default reply to a GET (or non-XML-RPC body) still mentions
	// "XML-RPC server accepts POST requests only." — the endpoint exists even
	// though the listMethods call itself didn't parse.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "XML-RPC server accepts POST requests only.")
	}))
	defer server.Close()

	runCtx := testRunContext(t)
	host := wpcore.FingerprintRecord{Target: server.URL, IsWordPress: true}
	finding := probeXMLRPC(context.Background(), server.Client(), runCtx, host)
	if !finding.Enabled {
		t.Fatalf("expected the GET fallback reply to still mark XML-RPC enabled: %+v", finding)
	}
	if len(finding.Methods) != 0 {
		t.Fatalf("fallback detection must not fabricate a method list: %+v", finding)
	}
}

func TestRunPublishesFindingsForEnabledHosts(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/xmlrpc.php" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/xml")
		_, _ = io.WriteString(w, listMethodsReply)
	}))
	defer server.Close()

	run := fullTestRun(t)
	writeFingerprint(t, run, server.URL)
	runCtx := modules.NewRunContext("example.com", "wp", false, run)
	if err := runCtx.AddArtifact("wp_fingerprint", modules.Artifact{Name: "wp_fingerprint", Type: "jsonl", Path: wpcore.OutputDir + "/wp-fingerprint.jsonl"}); err != nil {
		t.Fatal(err)
	}

	result, err := New().Run(context.Background(), runCtx, nil)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Status != "completed" {
		t.Fatalf("status = %q, want completed", result.Status)
	}
	if _, ok := runCtx.GetArtifact(reportName); !ok {
		t.Fatal("wp_xmlrpc artifact was not published")
	}

	data, err := os.ReadFile(run.Path(outputRel))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "\"enabled\":true") {
		t.Fatalf("output did not record the enabled endpoint: %s", data)
	}
	if !strings.Contains(string(data), "\"has_multicall\":true") {
		t.Fatalf("output lost the multicall signal: %s", data)
	}
}

func TestRunNoWordPressHostsSkipsProbing(t *testing.T) {
	run := fullTestRun(t)
	writeFile(t, run.Path(wpcore.OutputDir, "wp-fingerprint.jsonl"), "")
	runCtx := modules.NewRunContext("example.com", "wp", false, run)
	if err := runCtx.AddArtifact("wp_fingerprint", modules.Artifact{Name: "wp_fingerprint", Type: "jsonl", Path: wpcore.OutputDir + "/wp-fingerprint.jsonl"}); err != nil {
		t.Fatal(err)
	}

	result, err := New().Run(context.Background(), runCtx, nil)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Status != "skipped" || result.Reason != "no WordPress detected" {
		t.Fatalf("status = %q reason = %q, want skipped/no WordPress detected", result.Status, result.Reason)
	}
}

func TestRunDryRunMakesNoRequests(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	run := fullTestRun(t)
	writeFingerprint(t, run, server.URL)
	runCtx := modules.NewRunContext("example.com", "wp", true, run)
	if err := runCtx.AddArtifact("wp_fingerprint", modules.Artifact{Name: "wp_fingerprint", Type: "jsonl", Path: wpcore.OutputDir + "/wp-fingerprint.jsonl"}); err != nil {
		t.Fatal(err)
	}

	if _, err := New().Run(context.Background(), runCtx, nil); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if called {
		t.Fatal("dry run must not contact the target")
	}
}

func fullTestRun(t *testing.T) *storage.Run {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{"00_meta", wpcore.OutputDir} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return &storage.Run{
		RootDir:     root,
		MetaDir:     filepath.Join(root, "00_meta"),
		CommandsLog: filepath.Join(root, "00_meta", "commands.log"),
	}
}

func writeFingerprint(t *testing.T, run *storage.Run, target string) {
	t.Helper()
	writeFile(t, run.Path(wpcore.OutputDir, "wp-fingerprint.jsonl"),
		`{"target":"`+target+`","is_wordpress":true,"core_version":"6.4.2","sources":["generator"],"confidence":"high","fetched_at":"2026-11-18T00:00:00Z"}`+"\n")
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestParseMethods(t *testing.T) {
	methods := parseMethods(listMethodsReply)
	want := []string{"pingback.ping", "system.listMethods", "system.multicall", "wp.getUsersBlogs"}
	if len(methods) != len(want) {
		t.Fatalf("parseMethods returned %d methods, want %d (%v)", len(methods), len(want), methods)
	}
	for i, method := range want {
		if methods[i] != method {
			t.Fatalf("methods[%d] = %q, want %q", i, methods[i], method)
		}
	}
}

func testRunContext(t *testing.T) *modules.RunContext {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{"00_meta"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	run := &storage.Run{
		RootDir:     root,
		MetaDir:     filepath.Join(root, "00_meta"),
		CommandsLog: filepath.Join(root, "00_meta", "commands.log"),
	}
	return modules.NewRunContext("example.com", "wp", false, run)
}
