package payloadgen

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

func TestRequiresAndProduces(t *testing.T) {
	if got, want := New().Requires(), []string{"alive_urls"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Requires() = %v, want %v", got, want)
	}
	if got, want := New().Produces(), []string{"payload_wordlists"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Produces() = %v, want %v", got, want)
	}
}

func TestRunGeneratesWordlists(t *testing.T) {
	run := testRun(t)
	writeFile(t, run.Path("05_content", "alive.txt"), "https://example.com/\n")
	writeFile(t, run.Path("06_vulns", "js-secrets.jsonl"),
		`{"url":"https://example.com/app.js","kind":"endpoint","pattern":"sensitive-api-endpoint","severity":"info","match":"/api/v1/users"}`+"\n"+
			`{"url":"https://example.com/app.js","kind":"secret","pattern":"aws-access-key-id","severity":"critical","match":"AKIAIOSFODNN7EXAMPLE"}`+"\n")
	writeFile(t, run.Path("03_fingerprint", "gau.txt"),
		"https://example.com/search?q=hello&page=2\nhttps://example.com/api?limit=10\n")
	writeFile(t, run.Path("03_fingerprint", "whatweb.txt"),
		"http://example.com WordPress[6.3] ApacheTomcat[9.0.79]\n")

	runCtx := modules.NewRunContext("example.com", "deep", false, run)
	for name, path := range map[string]string{
		"alive_urls":      "05_content/alive.txt",
		"js_secrets":      "06_vulns/js-secrets.jsonl",
		"historical_urls": "03_fingerprint/gau.txt",
		"whatweb_raw":     "03_fingerprint/whatweb.txt",
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
	if _, ok := runCtx.GetArtifact("payload_wordlists"); !ok {
		t.Fatal("payload_wordlists artifact was not published")
	}

	apiPaths := readLines(t, run.Path(outputDir, fileAPIPaths))
	if !reflect.DeepEqual(apiPaths, []string{"/api/v1/users", "/api/v1/users.json"}) {
		t.Fatalf("api-paths = %v", apiPaths)
	}

	apiEndpoints := readLines(t, run.Path(outputDir, fileAPIEndpoints))
	if !reflect.DeepEqual(apiEndpoints, []string{"https://example.com/api/v1/users"}) {
		t.Fatalf("api-endpoints = %v", apiEndpoints)
	}

	params := readLines(t, run.Path(outputDir, fileParameters))
	if !reflect.DeepEqual(params, []string{"limit", "page", "q"}) {
		t.Fatalf("parameters = %v", params)
	}

	techPaths := readLines(t, run.Path(outputDir, fileTechEndpoints))
	wantTech := dedupe(techEndpoints["wordpress"])
	sort.Strings(wantTech)
	if !reflect.DeepEqual(techPaths, wantTech) {
		t.Fatalf("tech-endpoints = %v, want %v", techPaths, wantTech)
	}

	manifest := readLines(t, run.Path(outputDir, fileManifest))
	if len(manifest) != 4 {
		t.Fatalf("manifest entries = %d, want 4: %v", len(manifest), manifest)
	}
}

func TestRunWithNoUpstreamsProducesEmptyManifest(t *testing.T) {
	run := testRun(t)
	writeFile(t, run.Path("05_content", "alive.txt"), "https://example.com/\n")
	runCtx := modules.NewRunContext("example.com", "deep", false, run)
	if err := runCtx.AddArtifact("alive_urls", modules.Artifact{Name: "alive_urls", Type: "text", Path: "05_content/alive.txt"}); err != nil {
		t.Fatal(err)
	}

	if _, err := New().Run(context.Background(), runCtx, nil); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	manifest, err := os.ReadFile(run.Path(outputDir, fileManifest))
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest) != 0 {
		t.Fatalf("expected empty manifest, got %q", manifest)
	}
}

func TestReadParameters(t *testing.T) {
	run := testRun(t)
	writeFile(t, run.Path("03_fingerprint", "gau.txt"),
		"https://example.com/x?a=1&b=2\nhttps://example.com/y?a=3&c=4&a=5\n")
	params, err := readParameters(run.Path("03_fingerprint", "gau.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(params, []string{"a", "b", "c"}) {
		t.Fatalf("params = %v", params)
	}
}

func testRun(t *testing.T) *storage.Run {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{"00_meta", "03_fingerprint", "04_payloads", "05_content", "06_vulns"} {
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
