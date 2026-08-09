package dnsbrute

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

func TestRequiresAndProduces(t *testing.T) {
	m := New("")
	if got, want := m.Requires(), []string{"subdomains"}; !equal(got, want) {
		t.Fatalf("Requires() = %v, want %v", got, want)
	}
	if got, want := m.Produces(), []string{"brute_subdomains"}; !equal(got, want) {
		t.Fatalf("Produces() = %v, want %v", got, want)
	}
}

func TestRunDryRunBuildsShufflednsCommand(t *testing.T) {
	run := testRun(t)
	writeFile(t, run.Path("01_subdomains", "subdomains.txt"), "example.com\n")

	runCtx := modules.NewRunContext("example.com", "web", true, run)
	if err := runCtx.AddArtifact("subdomains", modules.Artifact{Name: "subdomains", Type: "text", Path: "01_subdomains/subdomains.txt"}); err != nil {
		t.Fatal(err)
	}

	if _, err := New("shuffledns").Run(context.Background(), runCtx, runner.NewDryRunExecutor(false)); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if art, ok := runCtx.GetArtifact("brute_subdomains"); !ok || art.Path != "01_subdomains/brute.txt" {
		t.Fatalf("brute_subdomains artifact missing: %+v", art)
	}

	log, err := os.ReadFile(run.CommandsLog)
	if err != nil {
		t.Fatal(err)
	}
	line := string(log)
	for _, want := range []string{"shuffledns", "-d", "-w", "-silent"} {
		if !strings.Contains(line, want) {
			t.Fatalf("commands log misses %q:\n%s", want, line)
		}
	}
}

func TestRunRealRunFailsWithoutWordlist(t *testing.T) {
	run := testRun(t)
	writeFile(t, run.Path("01_subdomains", "subdomains.txt"), "example.com\n")

	runCtx := modules.NewRunContext("example.com", "web", false, run)
	if err := runCtx.AddArtifact("subdomains", modules.Artifact{Name: "subdomains", Type: "text", Path: "01_subdomains/subdomains.txt"}); err != nil {
		t.Fatal(err)
	}

	_, err := New("shuffledns").Run(context.Background(), runCtx, runner.NewDryRunExecutor(false))
	if err == nil || !strings.Contains(err.Error(), "no DNS wordlist found") {
		t.Fatalf("expected wordlist error, got: %v", err)
	}
}

func testRun(t *testing.T) *storage.Run {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "00_meta"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "01_subdomains"), 0755); err != nil {
		t.Fatal(err)
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

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
