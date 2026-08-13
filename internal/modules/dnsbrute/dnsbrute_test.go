package dnsbrute

import (
	"context"
	"fmt"
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
	for _, want := range []string{"shuffledns", "-d", "example.com", "-w", "-r", "-mode", "bruteforce", "-silent"} {
		if !strings.Contains(line, want) {
			t.Fatalf("commands log misses %q:\n%s", want, line)
		}
	}
	if strings.Contains(line, "-d "+run.Path("01_subdomains", "subdomains.txt")) {
		t.Fatalf("the artifact file path must never be passed to -d (shuffledns takes domains):\n%s", line)
	}
}

func TestRunFailsWithoutSubdomainsArtifact(t *testing.T) {
	run := testRun(t)
	runCtx := modules.NewRunContext("example.com", "web", false, run)

	_, err := New("shuffledns").Run(context.Background(), runCtx, runner.NewDryRunExecutor(false))
	if err == nil || !strings.Contains(err.Error(), "subdomains") {
		t.Fatalf("expected artifact error, got: %v", err)
	}
}

func TestReadDomainsDedupesAndCaps(t *testing.T) {
	path := filepath.Join(t.TempDir(), "subs.txt")
	var lines []string
	// maxBruteforceDomains+5 distinct domains plus duplicates of the first.
	for i := 0; i < maxBruteforceDomains+5; i++ {
		lines = append(lines, fmt.Sprintf("d%d.example.com\n", i))
	}
	lines = append(lines, "d0.example.com\n", "d0.example.com\n", "  d1.example.com  \n")
	writeFile(t, path, strings.Join(lines, ""))

	domains, err := readDomains(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(domains) != maxBruteforceDomains {
		t.Fatalf("readDomains() = %d entries, want cap %d", len(domains), maxBruteforceDomains)
	}
	if domains[0] != "d0.example.com" || domains[1] != "d1.example.com" || domains[2] != "d2.example.com" {
		t.Fatalf("unexpected dedup order: %v", domains)
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
