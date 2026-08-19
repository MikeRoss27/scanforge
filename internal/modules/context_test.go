package modules

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	scanScope "github.com/MikeRoss27/scanforge/internal/scope"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

func TestRunContextArtifacts(t *testing.T) {
	ctx := NewRunContext("example.com", "passive", false, nil)

	if err := ctx.AddArtifact("subdomains", Artifact{
		Name: "subdomains",
		Type: "text",
		Path: "01_subdomains/subfinder.txt",
	}); err != nil {
		t.Fatalf("unexpected error from AddArtifact: %v", err)
	}

	art, ok := ctx.GetArtifact("subdomains")
	if !ok {
		t.Fatal("expected to get artifact")
	}
	if art.Path != "01_subdomains/subfinder.txt" {
		t.Fatalf("unexpected path: %s", art.Path)
	}

	if _, ok := ctx.GetArtifact("missing"); ok {
		t.Fatal("expected missing artifact to return false")
	}

	_, err := ctx.MustArtifact("subdomains")
	if err != nil {
		t.Fatalf("unexpected error from MustArtifact: %v", err)
	}

	_, err = ctx.MustArtifact("missing")
	if err == nil {
		t.Fatal("expected error from MustArtifact for missing artifact")
	}
}

func TestAddArtifactFiltersTargetsBeforePublishing(t *testing.T) {
	root := t.TempDir()
	run := &storage.Run{
		RootDir:  root,
		MetaDir:  filepath.Join(root, "00_meta"),
		Manifest: storage.RunManifest{Outputs: make(map[string]string)},
	}
	if err := os.MkdirAll(run.MetaDir, 0755); err != nil {
		t.Fatal(err)
	}

	scope := &scanScope.Scope{
		ExactHosts: map[string]struct{}{"example.com": {}},
		Wildcards:  []string{"example.com"},
		CIDRs:      mustCIDRs(t, "10.20.0.0/16"),
	}
	ctx := NewRunContext("example.com", "full", false, run, scope)

	artifactPath := filepath.Join(root, "discovered.txt")
	input := strings.Join([]string{
		"https://example.com/login",
		"https://redirect.evil.test/phish",
		"api.example.com:443",
		"outside.test:8080",
		"10.20.4.8:8443",
		"10.21.4.8:8443",
	}, "\n") + "\n"
	if err := os.WriteFile(artifactPath, []byte(input), 0644); err != nil {
		t.Fatal(err)
	}

	err := ctx.AddArtifact("alive_urls", Artifact{
		Name: "alive_urls",
		Type: "text",
		Path: "discovered.txt",
	})
	if err != nil {
		t.Fatalf("AddArtifact() error = %v", err)
	}

	filtered, err := os.ReadFile(artifactPath)
	if err != nil {
		t.Fatal(err)
	}
	want := "https://example.com/login\napi.example.com:443\n10.20.4.8:8443\n"
	if string(filtered) != want {
		t.Fatalf("filtered artifact = %q, want %q", filtered, want)
	}
	if _, ok := ctx.GetArtifact("alive_urls"); !ok {
		t.Fatal("filtered artifact was not published")
	}

	logPath := filepath.Join(run.MetaDir, "scope-rejections.jsonl")
	logFile, err := os.Open(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = logFile.Close() }()

	var rejected []scopeRejection
	scanner := bufio.NewScanner(logFile)
	for scanner.Scan() {
		var entry scopeRejection
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			t.Fatalf("invalid rejection log entry: %v", err)
		}
		rejected = append(rejected, entry)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(rejected) != 3 {
		t.Fatalf("rejection count = %d, want 3", len(rejected))
	}
	if rejected[0].Artifact != "alive_urls" || rejected[0].Path != "discovered.txt" {
		t.Fatalf("rejection lacks provenance: %+v", rejected[0])
	}
	if got := run.Manifest.Outputs["scope_rejections"]; got != "00_meta/scope-rejections.jsonl" {
		t.Fatalf("manifest rejection log = %q", got)
	}
}

// Crawled and historical URLs can exceed bufio.Scanner's 64KB default token
// limit; the scope filter must keep them instead of failing the artifact.
func TestAddArtifactFiltersLinesLongerThanDefaultScannerLimit(t *testing.T) {
	root := t.TempDir()
	run := &storage.Run{
		RootDir:  root,
		MetaDir:  filepath.Join(root, "00_meta"),
		Manifest: storage.RunManifest{Outputs: make(map[string]string)},
	}
	if err := os.MkdirAll(run.MetaDir, 0755); err != nil {
		t.Fatal(err)
	}

	scope := &scanScope.Scope{
		ExactHosts: map[string]struct{}{"example.com": {}},
		Wildcards:  []string{"example.com"},
	}
	ctx := NewRunContext("example.com", "full", false, run, scope)

	longURL := "https://example.com/path?" + strings.Repeat("a", 128*1024)
	artifactPath := filepath.Join(root, "crawled.txt")
	input := longURL + "\n" + "https://outside.test/x\n"
	if err := os.WriteFile(artifactPath, []byte(input), 0644); err != nil {
		t.Fatal(err)
	}

	err := ctx.AddArtifact("crawled_urls", Artifact{
		Name: "crawled_urls",
		Type: "text",
		Path: "crawled.txt",
	})
	if err != nil {
		t.Fatalf("AddArtifact() error = %v, want the long in-scope line to survive filtering", err)
	}

	filtered, err := os.ReadFile(artifactPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(filtered) != longURL+"\n" {
		t.Fatalf("filtered artifact length = %d, want only the %d-byte in-scope URL", len(filtered), len(longURL)+1)
	}
	if got := ctx.RejectedCount("crawled_urls"); got != 1 {
		t.Fatalf("RejectedCount() = %d, want 1", got)
	}
}

func TestAddArtifactDryRunDoesNotRequireOutputFile(t *testing.T) {
	scope := &scanScope.Scope{ExactHosts: map[string]struct{}{"example.com": {}}}
	run := &storage.Run{RootDir: t.TempDir()}
	ctx := NewRunContext("example.com", "web", true, run, scope)

	if err := ctx.AddArtifact("subdomains", Artifact{
		Name: "subdomains",
		Type: "text",
		Path: "missing.txt",
	}); err != nil {
		t.Fatalf("dry-run AddArtifact() error = %v", err)
	}
	if _, ok := ctx.GetArtifact("subdomains"); !ok {
		t.Fatal("dry-run artifact was not published")
	}
}

func TestAddArtifactDoesNotFilterNonTargetText(t *testing.T) {
	root := t.TempDir()
	run := &storage.Run{RootDir: root, MetaDir: filepath.Join(root, "00_meta")}
	scope := &scanScope.Scope{ExactHosts: map[string]struct{}{"example.com": {}}}
	ctx := NewRunContext("example.com", "web", false, run, scope)

	path := filepath.Join(root, "whatweb.txt")
	const contents = "Apache[HTTPServer], Country[UNITED STATES]\n"
	if err := os.WriteFile(path, []byte(contents), 0644); err != nil {
		t.Fatal(err)
	}
	if err := ctx.AddArtifact("technologies_raw", Artifact{
		Name: "technologies_raw",
		Type: "text",
		Path: "whatweb.txt",
	}); err != nil {
		t.Fatalf("AddArtifact() error = %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != contents {
		t.Fatalf("non-target artifact was modified: %q", got)
	}
}

func TestAddArtifactScopedFlagFiltersUnknownArtifactNames(t *testing.T) {
	root := t.TempDir()
	run := &storage.Run{
		RootDir:  root,
		MetaDir:  filepath.Join(root, "00_meta"),
		Manifest: storage.RunManifest{Outputs: make(map[string]string)},
	}
	if err := os.MkdirAll(run.MetaDir, 0755); err != nil {
		t.Fatal(err)
	}

	scope := &scanScope.Scope{
		ExactHosts: map[string]struct{}{"example.com": {}},
		Wildcards:  []string{"example.com"},
	}
	ctx := NewRunContext("example.com", "full", false, run, scope)

	// A future module producing a host list under a name that is NOT in the
	// legacy scopedTextArtifacts allowlist must still be filtered when it
	// declares Scoped: true. This is the regression guard for the explicit
	// opt-in mechanism.
	artifactPath := filepath.Join(root, "vhosts.txt")
	input := "vhost.example.com\nvhost.outside.test\n"
	if err := os.WriteFile(artifactPath, []byte(input), 0644); err != nil {
		t.Fatal(err)
	}

	err := ctx.AddArtifact("vhosts", Artifact{
		Name:   "vhosts",
		Type:   "text",
		Path:   "vhosts.txt",
		Scoped: true,
	})
	if err != nil {
		t.Fatalf("AddArtifact() error = %v", err)
	}

	filtered, err := os.ReadFile(artifactPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(filtered) != "vhost.example.com\n" {
		t.Fatalf("filtered artifact = %q, want only the in-scope host", filtered)
	}
	if got := ctx.RejectedCount("vhosts"); got != 1 {
		t.Fatalf("RejectedCount() = %d, want 1", got)
	}
}

func TestRunContextEmitFindingNoSinkIsNoop(t *testing.T) {
	ctx := NewRunContext("example.com", "passive", false, nil)
	// Must not panic when no sink was installed (e.g. a module test that
	// builds a RunContext directly without going through the orchestrator).
	ctx.EmitFinding(Finding{Module: "nuclei", Title: "test"})
}

func TestRunContextEmitFindingCallsSink(t *testing.T) {
	ctx := NewRunContext("example.com", "passive", false, nil)

	var got []Finding
	ctx.SetFindingSink(func(f Finding) {
		got = append(got, f)
	})

	ctx.EmitFinding(Finding{Module: "nuclei", Severity: "critical", Title: "exposed-git-config", Target: "https://example.com"})

	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got[0].Module != "nuclei" || got[0].Severity != "critical" || got[0].Title != "exposed-git-config" || got[0].Target != "https://example.com" {
		t.Fatalf("unexpected finding: %+v", got[0])
	}
}

func TestRunContextEmitWarningCallsSink(t *testing.T) {
	ctx := NewRunContext("example.com", "passive", false, nil)

	var got []string
	ctx.SetWarningSink(func(message string) {
		got = append(got, message)
	})

	ctx.EmitWarning("0 JS files")
	ctx.EmitWarning("more trouble")

	if len(got) != 2 || got[0] != "0 JS files" || got[1] != "more trouble" {
		t.Fatalf("unexpected warnings: %v", got)
	}
}

func TestRunContextRejectedCountTracksScopeFilter(t *testing.T) {
	root := t.TempDir()
	run := &storage.Run{RootDir: root, MetaDir: filepath.Join(root, "00_meta")}
	if err := os.MkdirAll(run.MetaDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(run.Path("04_surface"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(run.Path("04_surface", "crawled.txt"),
		[]byte("https://cdn.example.net/app.js\nhttps://example.com/app.js\nhttps://other.example.net/x.js\n"), 0644); err != nil {
		t.Fatal(err)
	}

	scope, err := scanScope.FromTarget("example.com", scanScope.ModeExact, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := NewRunContext("example.com", "web", false, run, scope)
	if err := ctx.AddArtifact("crawled_urls", Artifact{Name: "crawled_urls", Type: "text", Path: "04_surface/crawled.txt"}); err != nil {
		t.Fatal(err)
	}

	if got := ctx.RejectedCount("crawled_urls"); got != 2 {
		t.Fatalf("RejectedCount() = %d, want 2", got)
	}
}

func mustCIDRs(t *testing.T, values ...string) []*net.IPNet {
	t.Helper()
	var cidrs []*net.IPNet
	for _, value := range values {
		_, cidr, err := net.ParseCIDR(value)
		if err != nil {
			t.Fatal(err)
		}
		cidrs = append(cidrs, cidr)
	}
	return cidrs
}
