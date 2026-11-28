package dnspermute

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
	if got, want := m.Produces(), []string{"permuted_subdomains"}; !equal(got, want) {
		t.Fatalf("Produces() = %v, want %v", got, want)
	}
}

func TestRunDryRunBuildsGotatorCommand(t *testing.T) {
	run := testRun(t)
	writeFile(t, run.Path("01_subdomains", "subdomains.txt"), "www.example.com\n")

	runCtx := modules.NewRunContext("example.com", "deep", true, run)
	if err := runCtx.AddArtifact("subdomains", modules.Artifact{Name: "subdomains", Type: "text", Path: "01_subdomains/subdomains.txt"}); err != nil {
		t.Fatal(err)
	}

	if _, err := New("gotator").Run(context.Background(), runCtx, runner.NewDryRunExecutor(false)); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if art, ok := runCtx.GetArtifact("permuted_subdomains"); !ok || art.Path != "01_subdomains/permute.txt" || !art.Scoped {
		t.Fatalf("permuted_subdomains artifact missing or unscoped: %+v", art)
	}

	log, err := os.ReadFile(run.CommandsLog)
	if err != nil {
		t.Fatal(err)
	}
	line := string(log)
	for _, want := range []string{"gotator", "-sub", "-perm", "-depth", "1", "-mindup", "-adv", "-silent"} {
		if !strings.Contains(line, want) {
			t.Fatalf("commands log misses %q:\n%s", want, line)
		}
	}
}

func TestRunFailsWithoutSubdomainsArtifact(t *testing.T) {
	run := testRun(t)
	runCtx := modules.NewRunContext("example.com", "deep", false, run)

	_, err := New("gotator").Run(context.Background(), runCtx, runner.NewDryRunExecutor(false))
	if err == nil || !strings.Contains(err.Error(), "subdomains") {
		t.Fatalf("expected artifact error, got: %v", err)
	}
}

func TestRunDryRunWithUnwrittenSubdomainsFallsBackToTarget(t *testing.T) {
	run := testRun(t)
	runCtx := modules.NewRunContext("example.com", "deep", true, run)
	// Artifact published by a dry-run subfinder: the file was never written.
	if err := runCtx.AddArtifact("subdomains", modules.Artifact{Name: "subdomains", Type: "text", Path: "01_subdomains/subdomains.txt"}); err != nil {
		t.Fatal(err)
	}
	if _, err := New("gotator").Run(context.Background(), runCtx, runner.NewDryRunExecutor(false)); err != nil {
		t.Fatalf("dry-run must not fail on an unwritten subdomains artifact: %v", err)
	}
	log, err := os.ReadFile(run.CommandsLog)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(log), run.Path("01_subdomains", "permute-seeds.txt")) {
		t.Fatalf("expected a -sub seed file in the command log:\n%s", log)
	}
}

func TestReadSeedsDedupesAndCaps(t *testing.T) {
	path := filepath.Join(t.TempDir(), "subs.txt")
	var lines []string
	for i := 0; i < maxPermuteSeedDomains+5; i++ {
		lines = append(lines, fmt.Sprintf("d%d.example.com\n", i))
	}
	lines = append(lines, "d0.example.com\n", "d0.example.com\n", "  d1.example.com  \n")
	writeFile(t, path, strings.Join(lines, ""))

	seeds, err := readSeeds(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(seeds) != maxPermuteSeedDomains {
		t.Fatalf("readSeeds() = %d entries, want cap %d", len(seeds), maxPermuteSeedDomains)
	}
	if seeds[0] != "d0.example.com" || seeds[1] != "d1.example.com" {
		t.Fatalf("unexpected dedup order: %v", seeds)
	}
}

func TestWriteCandidatesDropsSeedsDedupesAndCaps(t *testing.T) {
	dir := t.TempDir()
	rawPath := filepath.Join(dir, "raw.txt")
	outPath := filepath.Join(dir, "out.txt")

	seeds := []string{"www.example.com", "api.example.com"}
	raw := []string{
		"www.example.com", // identical to a seed: must be dropped
		"dev.example.com",
		"dev.example.com", // duplicate: must be deduped
		"  staging.example.com  ",
		"",
	}
	writeFile(t, rawPath, strings.Join(raw, "\n")+"\n")

	if err := writeCandidates(rawPath, outPath, seeds); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Fields(string(data))
	want := []string{"dev.example.com", "staging.example.com"}
	if !equal(got, want) {
		t.Fatalf("writeCandidates() = %v, want %v", got, want)
	}
}

func TestWriteCandidatesCapsAtMax(t *testing.T) {
	dir := t.TempDir()
	rawPath := filepath.Join(dir, "raw.txt")
	outPath := filepath.Join(dir, "out.txt")

	var lines []string
	for i := 0; i < maxPermutedCandidates+10; i++ {
		lines = append(lines, fmt.Sprintf("d%d.example.com", i))
	}
	writeFile(t, rawPath, strings.Join(lines, "\n")+"\n")

	if err := writeCandidates(rawPath, outPath, nil); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Fields(string(data))
	if len(got) != maxPermutedCandidates {
		t.Fatalf("writeCandidates() produced %d lines, want cap %d", len(got), maxPermutedCandidates)
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
