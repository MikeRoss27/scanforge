package alterx

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

func newRun(t *testing.T) *storage.Run {
	t.Helper()
	root := t.TempDir()
	for _, d := range []string{"00_meta", "01_subdomains"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0755); err != nil {
			t.Fatal(err)
		}
	}
	return &storage.Run{RootDir: root, MetaDir: filepath.Join(root, "00_meta"), CommandsLog: filepath.Join(root, "00_meta", "commands.log")}
}

func writeSubdomains(t *testing.T, run *storage.Run, lines ...string) modules.Artifact {
	t.Helper()
	path := run.Path("01_subdomains", "subdomains.txt")
	content := ""
	if len(lines) > 0 {
		content = strings.Join(lines, "\n") + "\n"
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return modules.Artifact{Name: "subdomains", Type: "text", Path: "01_subdomains/subdomains.txt"}
}

func TestRunDryRunRecordsCommandWithoutExecution(t *testing.T) {
	run := newRun(t)
	runCtx := modules.NewRunContext("example.com", "recon", true, run)
	if err := runCtx.AddArtifact("subdomains", writeSubdomains(t, run, "www.example.com")); err != nil {
		t.Fatal(err)
	}

	executor := runner.NewDryRunExecutor(false)
	res, err := New("alterx-test").Run(context.Background(), runCtx, executor)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Status != "completed" {
		t.Fatalf("status = %q, want completed", res.Status)
	}

	log, err := os.ReadFile(run.CommandsLog)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(log), "alterx-test") || !strings.Contains(string(log), "-enrich") {
		t.Fatalf("planned command not recorded: %q", log)
	}

	if _, ok := runCtx.GetArtifact("altered_subdomains"); !ok {
		t.Fatal("altered_subdomains must be published even in dry run, so the DAG proceeds")
	}
}

func TestRunDryRunFallsBackToTargetWhenSeedsEmpty(t *testing.T) {
	run := newRun(t)
	runCtx := modules.NewRunContext("example.com", "recon", true, run)
	if err := runCtx.AddArtifact("subdomains", writeSubdomains(t, run)); err != nil {
		t.Fatal(err)
	}

	executor := runner.NewDryRunExecutor(false)
	if _, err := New("alterx-test").Run(context.Background(), runCtx, executor); err != nil {
		t.Fatalf("Run: %v", err)
	}

	seeds, err := os.ReadFile(run.Path("01_subdomains", "alterx-seeds.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(seeds)) != "example.com" {
		t.Fatalf("seed file = %q, want the scan target as fallback seed", seeds)
	}
}

func TestRunErrorsOnEmptySubdomainsWithoutDryRun(t *testing.T) {
	run := newRun(t)
	runCtx := modules.NewRunContext("example.com", "recon", false, run)
	if err := runCtx.AddArtifact("subdomains", writeSubdomains(t, run)); err != nil {
		t.Fatal(err)
	}

	executor := runner.NewDryRunExecutor(false)
	if _, err := New("alterx-test").Run(context.Background(), runCtx, executor); err == nil {
		t.Fatal("expected an error for an empty subdomains artifact outside dry run")
	}
}

func TestWriteCandidatesDedupsStripsSeedsAndCaps(t *testing.T) {
	dir := t.TempDir()
	rawPath := filepath.Join(dir, "raw.txt")
	outPath := filepath.Join(dir, "out.txt")

	raw := "dev.example.com\nexample.com\nDEV.example.com\nstaging.example.com\nstaging.example.com\n"
	if err := os.WriteFile(rawPath, []byte(raw), 0644); err != nil {
		t.Fatal(err)
	}

	if err := writeCandidates([]string{"example.com"}, rawPath, outPath, 5000); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	want := "dev.example.com\nstaging.example.com\n"
	if string(got) != want {
		t.Fatalf("writeCandidates = %q, want %q", got, want)
	}
}

func TestWriteCandidatesCapsAtMax(t *testing.T) {
	dir := t.TempDir()
	rawPath := filepath.Join(dir, "raw.txt")
	outPath := filepath.Join(dir, "out.txt")

	var lines []string
	for i := 0; i < 10; i++ {
		lines = append(lines, strings.Repeat("a", 1)+".example.com"+string(rune('a'+i)))
	}
	if err := os.WriteFile(rawPath, []byte(strings.Join(lines, "\n")+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := writeCandidates(nil, rawPath, outPath, 3); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	gotLines := strings.Split(strings.TrimRight(string(got), "\n"), "\n")
	if len(gotLines) != 3 {
		t.Fatalf("writeCandidates produced %d lines, want cap of 3: %v", len(gotLines), gotLines)
	}
}

func TestWriteCandidatesMissingRawFileYieldsEmptyOutput(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "out.txt")

	if err := writeCandidates([]string{"example.com"}, filepath.Join(dir, "missing.txt"), outPath, 5000); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty output, got %q", got)
	}
}
