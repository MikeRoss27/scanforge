package attacksurface

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/modules"
	scanScope "github.com/MikeRoss27/scanforge/internal/scope"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

func TestRequiresAndProduces(t *testing.T) {
	if got, want := New().Requires(), []string{"alive_urls", "crawled_urls", "js_secrets"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Requires() = %v, want %v", got, want)
	}
	if got, want := New().Produces(), []string{"attack_surface_urls"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Produces() = %v, want %v", got, want)
	}
}

func TestRunMergesAllSources(t *testing.T) {
	run := testRun(t)
	writeFile(t, run.Path("05_content", "alive.txt"),
		"https://example.com/\nhttps://example.com/\nhttps://api.example.com/\n")
	writeFile(t, run.Path("05_content", "katana.txt"),
		"https://example.com/\nhttps://example.com/admin\nhttps://example.com/app.js\n")
	writeFile(t, run.Path("05_content", "ffuf.json"),
		`{"results":[{"url":"https://example.com/admin/login"},{"url":"https://example.com/api"}]}`+"\n")
	writeFile(t, run.Path("06_vulns", "js-secrets.jsonl"),
		`{"url":"https://example.com/app.js","kind":"endpoint","pattern":"sensitive-api-endpoint","severity":"info","match":"/api/v1/users"}`+"\n"+
			`{"url":"https://example.com/app.js","kind":"secret","pattern":"aws-access-key-id","severity":"critical","match":"AKIAIOSFODNN7EXAMPLE"}`+"\n")

	runCtx := modules.NewRunContext("example.com", "deep", false, run)
	for name, path := range map[string]string{
		"alive_urls":       "05_content/alive.txt",
		"crawled_urls":     "05_content/katana.txt",
		"discovered_paths": "05_content/ffuf.json",
		"js_secrets":       "06_vulns/js-secrets.jsonl",
	} {
		if err := runCtx.AddArtifact(name, modules.Artifact{Name: name, Type: "text", Path: path}); err != nil {
			t.Fatal(err)
		}
	}

	result, err := New().Run(context.Background(), runCtx, nil)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Status != "completed" {
		t.Fatalf("Run() status = %q, want completed", result.Status)
	}
	if _, ok := runCtx.GetArtifact("attack_surface_urls"); !ok {
		t.Fatal("attack_surface_urls artifact was not published")
	}

	got := readLines(t, run.Path(outputRel))
	want := []string{
		"https://example.com/",
		"https://api.example.com/",
		"https://example.com/admin",
		"https://example.com/app.js",
		"https://example.com/admin/login",
		"https://example.com/api",
		"https://example.com/api/v1/users",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("attack surface = %v, want %v", got, want)
	}
}

func TestRunToleratesMissingUpstreams(t *testing.T) {
	run := testRun(t)
	writeFile(t, run.Path("05_content", "alive.txt"), "https://example.com/\n")

	runCtx := modules.NewRunContext("example.com", "vuln", false, run)
	if err := runCtx.AddArtifact("alive_urls", modules.Artifact{Name: "alive_urls", Type: "text", Path: "05_content/alive.txt"}); err != nil {
		t.Fatal(err)
	}

	if _, err := New().Run(context.Background(), runCtx, nil); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	got := readLines(t, run.Path(outputRel))
	if !reflect.DeepEqual(got, []string{"https://example.com/"}) {
		t.Fatalf("attack surface = %v, want only the alive URL", got)
	}
}

func TestRunFailsWithoutAliveURLs(t *testing.T) {
	run := testRun(t)
	runCtx := modules.NewRunContext("example.com", "deep", false, run)

	if _, err := New().Run(context.Background(), runCtx, nil); err == nil {
		t.Fatal("expected an error when alive_urls is missing")
	}
}

func TestRunDropsOutOfScopeJSEndpoints(t *testing.T) {
	run := testRun(t)
	writeFile(t, run.Path("05_content", "alive.txt"), "https://example.com/\n")
	writeFile(t, run.Path("05_content", "katana.txt"), "https://example.com/\n")
	// An in-scope JS bundle references an absolute third-party endpoint; the
	// attack surface must not propagate it.
	writeFile(t, run.Path("06_vulns", "js-secrets.jsonl"),
		`{"url":"https://example.com/app.js","kind":"endpoint","pattern":"sensitive-api-endpoint","severity":"info","match":"https://attacker.example/steal"}`+"\n")

	scope, err := scanScope.FromTarget("example.com", scanScope.ModeDomain, nil, nil)
	if err != nil {
		t.Fatalf("build scope: %v", err)
	}
	runCtx := modules.NewRunContext("example.com", "deep", false, run, scope)
	for name, path := range map[string]string{
		"alive_urls":   "05_content/alive.txt",
		"crawled_urls": "05_content/katana.txt",
		"js_secrets":   "06_vulns/js-secrets.jsonl",
	} {
		if err := runCtx.AddArtifact(name, modules.Artifact{Name: name, Type: "text", Path: path}); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := New().Run(context.Background(), runCtx, nil); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	got := readLines(t, run.Path(outputRel))
	if !reflect.DeepEqual(got, []string{"https://example.com/"}) {
		t.Fatalf("attack surface = %v, want only the in-scope URL", got)
	}
}

func TestResolveEndpoint(t *testing.T) {
	cases := map[string]string{
		"https://example.com/app.js,/api/v1/users":    "https://example.com/api/v1/users",
		"https://example.com/app.js,../admin":         "https://example.com/admin",
		"https://example.com/app.js,https://x.test/a": "https://x.test/a",
		"https://example.com/app.js,not a url":        "",
	}
	for input, want := range cases {
		parts := strings.SplitN(input, ",", 2)
		if got := resolveEndpoint(parts[0], parts[1]); got != want {
			t.Errorf("resolveEndpoint(%q, %q) = %q, want %q", parts[0], parts[1], got, want)
		}
	}
}

func testRun(t *testing.T) *storage.Run {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{"00_meta", "04_surface", "05_content", "06_vulns"} {
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

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return nil
	}
	return lines
}
