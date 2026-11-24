package app

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/assets"
	"github.com/MikeRoss27/scanforge/internal/console"
	"github.com/MikeRoss27/scanforge/internal/report"
	"github.com/MikeRoss27/scanforge/internal/scope"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

func incrementalSession(t *testing.T, workspace string, opts RunOptions, scopeSHA, status string, versions map[string]string) *runSession {
	t.Helper()
	sc, err := scope.FromTarget("example.com", scope.ModeDomain, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	run, err := storage.NewRunStore(workspace).Create("example.com")
	if err != nil {
		t.Fatal(err)
	}
	run.Manifest.ScopeSHA256 = scopeSHA
	run.Manifest.Status = status
	for _, name := range []string{"subfinder", "httpx", "nuclei"} {
		run.SetModule(storage.ModuleResult{Name: name, Status: storage.ModuleCompleted})
	}
	return &runSession{
		opts:        opts,
		effective:   &effectiveScope{value: sc},
		scanRun:     run,
		console:     console.New(console.Options{}),
		incremental: incrementalState{toolVersions: versions},
	}
}

func siteReport(hosts ...string) *report.Report {
	rep := report.NewReport("example.com", "web")
	for _, h := range hosts {
		a := rep.GetOrCreateAsset(h)
		a.HTTP = []report.HTTPService{{URL: "https://" + h, StatusCode: 200, Title: h}}
	}
	return rep
}

func statuses(t *testing.T, workspace string) map[string]string {
	t.Helper()
	recs, err := listAssets(storage.TargetDir(workspace, "example.com"), AssetsOptions{Target: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, r := range recs {
		out[r.Type+":"+r.Value] = r.Status
	}
	return out
}

func TestIncrementalTwoRunsNewAndGone(t *testing.T) {
	ws := t.TempDir()
	versions := map[string]string{"nuclei": "3.0"}

	// Run 1 (not incremental): a and b. It also seeds the history.
	s1 := incrementalSession(t, ws, RunOptions{}, "scope-1", "completed", versions)
	if focus := s1.prepareIncremental(); focus != nil {
		t.Fatal("a non-incremental run must not install a focus")
	}
	s1.recordAssets(siteReport("a.example.com", "b.example.com"))

	got := statuses(t, ws)
	if got["subdomain:a.example.com"] != assets.StatusNew || got["url:https://b.example.com"] != assets.StatusNew {
		t.Fatalf("after run 1: %v", got)
	}

	// Run 2 (incremental): b disappears, c appears, a is unchanged.
	s2 := incrementalSession(t, ws, RunOptions{Incremental: true}, "scope-1", "completed", versions)
	focus := s2.prepareIncremental()
	if focus == nil {
		t.Fatal("expected an incremental focus")
	}
	if s2.incremental.invalidated {
		t.Fatal("same scope and versions must keep the cache valid")
	}
	for url, want := range map[string]bool{
		"https://a.example.com": false, // unchanged: skipped by the active modules
		"https://c.example.com": true,  // new: scanned
		"https://b.example.com": false,
	} {
		if got := focus.Keep(url); got != want {
			t.Errorf("Keep(%s) = %v, want %v", url, got, want)
		}
	}
	s2.recordAssets(siteReport("a.example.com", "c.example.com"))
	got = statuses(t, ws)
	want := map[string]string{
		"subdomain:a.example.com":   assets.StatusUnchanged,
		"subdomain:b.example.com":   assets.StatusGone,
		"subdomain:c.example.com":   assets.StatusNew,
		"url:https://b.example.com": assets.StatusGone,
		"url:https://c.example.com": assets.StatusNew,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}

	// assets --new / --gone filter the listing.
	dir := storage.TargetDir(ws, "example.com")
	gone, err := listAssets(dir, AssetsOptions{Target: "example.com", Gone: true})
	if err != nil || len(gone) != 2 { // subdomain b and url b
		t.Fatalf("gone = %v err %v", gone, err)
	}
	newRecs, err := listAssets(dir, AssetsOptions{Target: "example.com", New: true})
	if err != nil || len(newRecs) != 2 {
		t.Fatalf("new = %v err %v", newRecs, err)
	}

	// Recording the same run twice (resume of a finished run) is a no-op.
	before, _ := os.ReadFile(filepath.Join(dir, assets.FileName))
	s2.incremental.history = nil // as a fresh session would after a resume
	s2.recordAssets(siteReport("a.example.com"))
	after, _ := os.ReadFile(filepath.Join(dir, assets.FileName))
	if string(before) != string(after) {
		t.Fatal("history changed when the same run was recorded twice")
	}
}

func TestIncrementalInvalidatedByScopeOrToolVersion(t *testing.T) {
	tests := []struct {
		name     string
		scopeSHA string
		versions map[string]string
	}{
		{"scope hash differs", "scope-2", map[string]string{"nuclei": "3.0"}},
		{"tool version differs", "scope-1", map[string]string{"nuclei": "3.1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ws := t.TempDir()
			s1 := incrementalSession(t, ws, RunOptions{}, "scope-1", "completed", map[string]string{"nuclei": "3.0"})
			s1.prepareIncremental()
			s1.recordAssets(siteReport("a.example.com"))

			s2 := incrementalSession(t, ws, RunOptions{Incremental: true}, tt.scopeSHA, "completed", tt.versions)
			focus := s2.prepareIncremental()
			if !s2.incremental.invalidated || focus == nil {
				t.Fatalf("expected an invalidated incremental run")
			}
			if !focus.Keep("https://a.example.com") {
				t.Fatal("an invalidated cache must scan everything")
			}
			s2.recordAssets(siteReport("a.example.com"))
			if got := statuses(t, ws)["url:https://a.example.com"]; got != assets.StatusNew {
				t.Fatalf("status = %q, want new", got)
			}
		})
	}
}

func TestIncrementalNeverReusesOutOfScopeHistory(t *testing.T) {
	ws := t.TempDir()
	dir := storage.TargetDir(ws, "example.com")
	// A history written under a wider scope.
	err := assets.Append(filepath.Join(dir, assets.FileName), []assets.Record{
		{Type: assets.TypeRun, Value: "old", ScopeSHA256: "scope-1"},
		{Type: assets.TypeURL, Value: "https://evil.org", Host: "https://evil.org", Status: assets.StatusUnchanged},
		{Type: assets.TypeURL, Value: "https://a.example.com", Host: "https://a.example.com", Status: assets.StatusUnchanged},
	})
	if err != nil {
		t.Fatal(err)
	}
	s := incrementalSession(t, ws, RunOptions{Incremental: true}, "scope-1", "completed", nil)
	focus := s.prepareIncremental()
	if focus == nil {
		t.Fatal("expected a focus")
	}
	if _, ok := s.incremental.history.Lookup(assets.TypeURL, "https://evil.org"); ok {
		t.Fatal("out-of-scope history entry was kept")
	}
	// The out-of-scope URL is unknown to the focus: it can only be kept
	// (scanned) if it ever reaches the module, which scope filtering prevents.
	if !focus.Keep("https://evil.org") {
		t.Fatal("unknown URLs must be kept, never silently trusted as unchanged")
	}
}

func TestRecordAssetsSkipsDryRunAndIncompleteRuns(t *testing.T) {
	tests := []struct {
		name   string
		opts   RunOptions
		status string
	}{
		{"dry run", RunOptions{DryRun: true}, "completed"},
		{"partial run", RunOptions{}, "partial"},
		{"failed run", RunOptions{}, "failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ws := t.TempDir()
			s := incrementalSession(t, ws, tt.opts, "scope-1", tt.status, nil)
			s.prepareIncremental()
			s.recordAssets(siteReport("a.example.com"))
			if _, err := os.Stat(filepath.Join(storage.TargetDir(ws, "example.com"), assets.FileName)); !os.IsNotExist(err) {
				t.Fatalf("history written for a %s (err=%v)", tt.name, err)
			}
		})
	}
}

func TestAssetsWithoutHistoryExplainsWhy(t *testing.T) {
	if _, err := listAssets(t.TempDir(), AssetsOptions{Target: "example.com"}); err == nil {
		t.Fatal("expected an error for a target without history")
	}
}
