package attacksurface

import (
	"context"
	"fmt"
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
	if got, want := New().Requires(), []string{"alive_urls"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Requires() = %v, want %v", got, want)
	}
	if got, want := New().SoftRequires(), []string{"crawled_urls", "discovered_paths", "js_secrets"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("SoftRequires() = %v, want %v", got, want)
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

// A killed or timed-out ffuf leaves a truncated JSON file. The module must
// salvage whatever full records are present instead of dying, so nuclei still
// gets its attack surface input.
func TestRunSalvagesTruncatedFfufJSON(t *testing.T) {
	run := testRun(t)
	writeFile(t, run.Path("05_content", "alive.txt"), "https://example.com/\n")
	writeFile(t, run.Path("05_content", "ffuf.json"),
		`{"results":[{"url":"https://example.com/admin"},{"url":"https://example.com/api"}]}`+"\n"+
			`{"results":[{"url":"https://example.com/truncated"`)

	runCtx := modules.NewRunContext("example.com", "deep", false, run)
	for name, path := range map[string]string{
		"alive_urls":       "05_content/alive.txt",
		"discovered_paths": "05_content/ffuf.json",
	} {
		if err := runCtx.AddArtifact(name, modules.Artifact{Name: name, Type: "text", Path: path}); err != nil {
			t.Fatal(err)
		}
	}

	_, err := New().Run(context.Background(), runCtx, nil)
	if err != nil {
		t.Fatalf("Run() must not fail on truncated ffuf output: %v", err)
	}
	if art, ok := runCtx.GetArtifact("attack_surface_urls"); !ok || art.Path != outputRel {
		t.Fatalf("attack_surface_urls must still be published: %+v", art)
	}
	if got := readLines(t, run.Path(outputRel)); len(got) != 3 {
		t.Fatalf("salvaged attack surface = %v, want the 3 complete URLs", got)
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

func TestCapPerHost(t *testing.T) {
	many := func(host string, n int) []string {
		out := make([]string, 0, n)
		for i := 0; i < n; i++ {
			out = append(out, fmt.Sprintf("https://%s/p%d", host, i))
		}
		return out
	}
	tests := []struct {
		name          string
		urls          []string
		limit         int
		wantKept      []string
		wantTruncated []hostTruncation
	}{
		{
			name:     "under the cap is untouched",
			urls:     many("a.test", 3),
			limit:    3,
			wantKept: many("a.test", 3),
		},
		{
			name:          "keeps the first URLs of a flooding host only",
			urls:          append(many("b.test", 5), many("a.test", 2)...),
			limit:         3,
			wantKept:      append(many("b.test", 3), many("a.test", 2)...),
			wantTruncated: []hostTruncation{{host: "b.test", total: 5}},
		},
		{
			name:          "host matching is case-insensitive and truncations are sorted",
			urls:          []string{"https://Z.test/1", "https://z.test/2", "https://y.test/1", "https://y.test/2"},
			limit:         1,
			wantKept:      []string{"https://Z.test/1", "https://y.test/1"},
			wantTruncated: []hostTruncation{{host: "y.test", total: 2}, {host: "z.test", total: 2}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kept, truncated := capPerHost(tt.urls, tt.limit)
			if !reflect.DeepEqual(kept, tt.wantKept) {
				t.Fatalf("kept = %v, want %v", kept, tt.wantKept)
			}
			if !reflect.DeepEqual(truncated, tt.wantTruncated) {
				t.Fatalf("truncated = %+v, want %+v", truncated, tt.wantTruncated)
			}
		})
	}
}

// TestRunCapsFloodingHost reproduces the 3873-URL attack surface that fed
// nuclei for 12+ minutes: one host's URLs are capped, other hosts and the
// alive URLs (listed first) survive, and the operator is warned.
func TestRunCapsFloodingHost(t *testing.T) {
	run := testRun(t)
	writeFile(t, run.Path("05_content", "alive.txt"), "https://voltlaunchr.com\nhttps://www.voltlaunchr.com\n")
	var b strings.Builder
	b.WriteString(`{"results":[`)
	for i := 0; i < 3871; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"url":"https://voltlaunchr.com/word%04d","status":403,"length":25103}`, i)
	}
	b.WriteString("]}\n")
	writeFile(t, run.Path("05_content", "ffuf.json"), b.String())

	runCtx := modules.NewRunContext("voltlaunchr.com", "deep", false, run)
	for name, path := range map[string]string{
		"alive_urls":       "05_content/alive.txt",
		"discovered_paths": "05_content/ffuf.json",
	} {
		if err := runCtx.AddArtifact(name, modules.Artifact{Name: name, Type: "text", Path: path}); err != nil {
			t.Fatal(err)
		}
	}
	var warnings []string
	runCtx.SetWarningSink(func(msg string) { warnings = append(warnings, msg) })

	if _, err := New().Run(context.Background(), runCtx, nil); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	got := readLines(t, run.Path(outputRel))
	if len(got) != maxURLsPerHost+1 {
		t.Fatalf("attack surface has %d URLs, want %d", len(got), maxURLsPerHost+1)
	}
	if got[0] != "https://voltlaunchr.com" || got[1] != "https://www.voltlaunchr.com" {
		t.Fatalf("alive URLs must survive the cap first, got %v", got[:2])
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "voltlaunchr.com has 3872 URLs") {
		t.Fatalf("warnings = %q, want one truncation warning for voltlaunchr.com", warnings)
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
