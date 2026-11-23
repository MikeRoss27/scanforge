package runindex

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	. "github.com/MikeRoss27/scanforge/internal/runindex/runindextest"
)

func TestFindingsKeepLeakedSecretsAndScrubOperatorCredentials(t *testing.T) {
	idx := New(WriteFixture(t))
	page, err := idx.Findings(RunID, FindingFilter{})
	if err != nil || page.Total != 2 {
		t.Fatalf("findings: %v %+v", err, page)
	}
	if page.Findings[0].Severity != "high" {
		t.Fatalf("expected most severe first, got %s", page.Findings[0].Severity)
	}
	out, err := idx.Encode(page, RunID)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, LeakedSecret) {
		t.Fatalf("leaked target secret must be returned unmasked: %s", s)
	}
	if strings.Contains(s, OperatorBearer) {
		t.Fatalf("operator bearer leaked: %s", s)
	}
}

func TestEvidenceFileScrubbedAndRestricted(t *testing.T) {
	idx := New(WriteFixture(t), "static-operator-api-key")
	ev, err := idx.Evidence(RunID, "", "06_vulns/nuclei.jsonl", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := idx.Encode(ev, RunID)
	s := string(out)
	if !strings.Contains(s, LeakedSecret) || strings.Contains(s, OperatorBearer) || strings.Contains(s, "sessionvalue99") {
		t.Fatalf("unexpected scrub result: %s", s)
	}
	for _, bad := range []string{"00_meta/commands.log", "../report.json", "06_vulns/../00_meta/commands.log", "/etc/passwd", "06_vulns/nuclei.jsonl/../../report.json", "report.json", "06_vulns/x.bin"} {
		if _, err := idx.Evidence(RunID, "", bad, 0, 0); err == nil {
			t.Errorf("evidence path %q must be rejected", bad)
		}
	}
}

func TestRunIDPathTraversalRejected(t *testing.T) {
	ws := WriteFixture(t)
	idx := New(ws)
	for _, id := range []string{"../etc/passwd", "..", "example.com/..", "../example.com/2026-01-01_00-00-00", "example.com/../example.com/x", "/etc/passwd", "example.com", "a/b/c", "example.com\\..", "", "example.com/%2e%2e"} {
		if _, err := idx.GetRun(id); !errors.Is(err, ErrInvalidRunID) {
			t.Errorf("GetRun(%q) err = %v, want ErrInvalidRunID", id, err)
		}
		if _, err := idx.Findings(id, FindingFilter{}); err == nil {
			t.Errorf("Findings(%q) must fail", id)
		}
	}
}

func TestSymlinkEscapeRejected(t *testing.T) {
	ws := WriteFixture(t)
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("nope"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(ws, "evil.com")); err != nil {
		t.Skip("symlink unsupported")
	}
	if _, err := New(ws).GetRun("evil.com/anything"); err == nil {
		t.Fatal("symlinked target dir escaping workspace must fail")
	}
	run := filepath.Join(ws, "example.com", "2026-01-01_00-00-00", "06_vulns")
	if err := os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(run, "link.txt")); err != nil {
		t.Skip("symlink unsupported")
	}
	if _, err := New(ws).Evidence(RunID, "", "06_vulns/link.txt", 0, 0); err == nil {
		t.Fatal("symlinked evidence file escaping run must fail")
	}
}

func TestListAndGetRun(t *testing.T) {
	idx := New(WriteFixture(t))
	runs, err := idx.ListRuns("example", 0)
	if err != nil || len(runs) != 1 || runs[0].RunID != RunID {
		t.Fatalf("list: %v %+v", err, runs)
	}
	d, err := idx.GetRun(RunID)
	if err != nil || !d.HasReport || d.FindingCount != 2 || d.AssetCount != 1 {
		t.Fatalf("get: %v %+v", err, d)
	}
	a, err := idx.Assets(RunID, "www", 0, 0)
	if err != nil || a.Total != 1 {
		t.Fatalf("assets: %v %+v", err, a)
	}
}
