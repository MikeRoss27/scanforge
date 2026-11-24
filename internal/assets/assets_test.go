package assets

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/MikeRoss27/scanforge/internal/report"
	"github.com/MikeRoss27/scanforge/internal/scope"
)

func mustScope(t *testing.T) *scope.Scope {
	t.Helper()
	sc, err := scope.FromTarget("example.com", scope.ModeDomain, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return sc
}

func reportWith(hosts map[string]string) *report.Report {
	rep := report.NewReport("example.com", "web")
	for host, title := range hosts {
		a := rep.GetOrCreateAsset(host)
		a.IPs = []string{"192.0.2.1"}
		a.HTTP = []report.HTTPService{{URL: "https://" + host, StatusCode: 200, Title: title}}
		a.Technologies = []string{"nginx"}
	}
	return rep
}

func statusOf(recs []Record, typ, value string) string {
	for _, r := range recs {
		if r.Type == typ && r.Value == value {
			return r.Status
		}
	}
	return ""
}

var allTypes = map[string]bool{
	TypeSubdomain: true, TypeHost: true, TypeURL: true, TypePort: true, TypeTech: true,
}

func TestTwoConsecutiveRunsTrackAppearAndDisappear(t *testing.T) {
	path := filepath.Join(t.TempDir(), "example.com", FileName)
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// Run 1: a and b.
	h1, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	recs1 := Reconcile(h1, Observe(reportWith(map[string]string{"a.example.com": "A", "b.example.com": "B"})),
		RunMeta{RunID: "run1", At: t0, ScopeSHA256: "s", Coverage: allTypes})
	if err := Append(path, recs1); err != nil {
		t.Fatal(err)
	}
	if got := statusOf(recs1, TypeSubdomain, "a.example.com"); got != StatusNew {
		t.Fatalf("run1 a = %q, want new", got)
	}

	// Run 2: b stays (title changes on a), c appears, b disappears.
	h2, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	recs2 := Reconcile(h2, Observe(reportWith(map[string]string{"a.example.com": "A2", "c.example.com": "C"})),
		RunMeta{RunID: "run2", At: t0.Add(time.Hour), ScopeSHA256: "s", Coverage: allTypes})
	if err := Append(path, recs2); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"c.example.com": StatusNew,
		"b.example.com": StatusGone,
	}
	for host, st := range want {
		if got := statusOf(recs2, TypeSubdomain, host); got != st {
			t.Errorf("run2 %s = %q, want %q", host, got, st)
		}
	}
	// a: same IPs so the subdomain is unchanged, but its URL changed.
	if got := statusOf(recs2, TypeSubdomain, "a.example.com"); got != StatusUnchanged {
		t.Errorf("run2 a subdomain = %q, want unchanged", got)
	}
	if got := statusOf(recs2, TypeURL, "https://a.example.com"); got != StatusChanged {
		t.Errorf("run2 a url = %q, want changed", got)
	}
	if got := statusOf(recs2, TypeURL, "https://b.example.com"); got != StatusGone {
		t.Errorf("run2 b url = %q, want gone", got)
	}

	// Final state: last line wins, first_seen preserved, run recorded.
	h3, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := h3.Lookup(TypeSubdomain, "a.example.com")
	if a.FirstSeen != t0.Format(time.RFC3339) || a.LastRunID != "run2" {
		t.Errorf("a = %+v", a)
	}
	b, _ := h3.Lookup(TypeSubdomain, "b.example.com")
	if b.Status != StatusGone {
		t.Errorf("b = %+v", b)
	}
	if !h3.HasRun("run1") || !h3.HasRun("run2") || h3.Last.Value != "run2" {
		t.Errorf("runs not recorded: %+v", h3.Last)
	}

	// A gone asset is not re-reported by the next run, and reappearing
	// makes it new again with its original first_seen.
	recs3 := Reconcile(h3, Observe(reportWith(map[string]string{"a.example.com": "A2", "b.example.com": "B"})),
		RunMeta{RunID: "run3", At: t0.Add(2 * time.Hour), ScopeSHA256: "s", Coverage: allTypes})
	if got := statusOf(recs3, TypeSubdomain, "b.example.com"); got != StatusNew {
		t.Errorf("reappeared b = %q, want new", got)
	}
	if got := statusOf(recs3, TypeSubdomain, "c.example.com"); got != StatusGone {
		t.Errorf("c = %q, want gone", got)
	}
}

func TestReconcileUncoveredTypesAreNeverGone(t *testing.T) {
	h := &History{Records: map[string]Record{
		key(TypeFinding, "nuclei|x|t|https://a.example.com"): {
			Type: TypeFinding, Value: "nuclei|x|t|https://a.example.com", Host: "https://a.example.com",
			Status: StatusNew, FirstSeen: "x",
		},
	}, runs: map[string]bool{}}
	tests := []struct {
		name     string
		coverage map[string]bool
		want     bool
	}{
		{"covered", map[string]bool{TypeFinding: true}, true},
		{"not covered", map[string]bool{TypeFinding: false}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recs := Reconcile(h, nil, RunMeta{RunID: "r", At: time.Now(), Coverage: tt.coverage})
			got := statusOf(recs, TypeFinding, "nuclei|x|t|https://a.example.com") == StatusGone
			if got != tt.want {
				t.Fatalf("gone = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCoverageFocusedRunDoesNotCoverPathsAndFindings(t *testing.T) {
	done := map[string]bool{"httpx": true, "katana": true, "nuclei": true}
	if c := Coverage(done, false); !c[TypePath] || !c[TypeFinding] || !c[TypeURL] {
		t.Errorf("full run coverage = %v", c)
	}
	if c := Coverage(done, true); c[TypePath] || c[TypeFinding] || !c[TypeURL] {
		t.Errorf("focused run coverage = %v", c)
	}
	if c := Coverage(map[string]bool{}, false); c[TypeURL] || c[TypeSubdomain] {
		t.Errorf("empty coverage = %v", c)
	}
}

func TestInvalidated(t *testing.T) {
	h := &History{Last: &Record{ScopeSHA256: "s1", ToolVersions: map[string]string{"nuclei": "3.0", "httpx": "1.0"}}}
	tests := []struct {
		name     string
		hist     *History
		scope    string
		versions map[string]string
		want     bool
	}{
		{"no previous run", &History{}, "s1", nil, false},
		{"identical", h, "s1", map[string]string{"nuclei": "3.0"}, false},
		{"scope changed", h, "s2", map[string]string{"nuclei": "3.0"}, true},
		{"tool upgraded", h, "s1", map[string]string{"nuclei": "3.1"}, true},
		{"tool only on one side", h, "s1", map[string]string{"katana": "1"}, false},
		{"versions unknown now", h, "s1", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.hist.Invalidated(tt.scope, tt.versions); got != tt.want {
				t.Fatalf("Invalidated = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestInvalidatedRunMarksEverythingNew(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	t0 := time.Now()
	h, _ := Load(path)
	obs := Observe(reportWith(map[string]string{"a.example.com": "A"}))
	if err := Append(path, Reconcile(h, obs, RunMeta{RunID: "r1", At: t0, Coverage: allTypes})); err != nil {
		t.Fatal(err)
	}
	h, _ = Load(path)
	recs := Reconcile(h, obs, RunMeta{RunID: "r2", At: t0, Coverage: allTypes, Invalidated: true})
	if got := statusOf(recs, TypeSubdomain, "a.example.com"); got != StatusNew {
		t.Fatalf("status = %q, want new", got)
	}
}

func TestFilterScopeDropsOutOfScopeAndUnscopedEntries(t *testing.T) {
	h := &History{Records: map[string]Record{}, runs: map[string]bool{}}
	for _, r := range []Record{
		{Type: TypeURL, Value: "https://a.example.com", Host: "https://a.example.com"},
		{Type: TypeURL, Value: "https://evil.org", Host: "https://evil.org"},
		{Type: TypeSubdomain, Value: "nohost.example.com"},
	} {
		h.Records[key(r.Type, r.Value)] = r
	}
	if dropped := h.FilterScope(mustScope(t)); dropped != 2 {
		t.Fatalf("dropped = %d, want 2", dropped)
	}
	if _, ok := h.Lookup(TypeURL, "https://a.example.com"); !ok || len(h.Records) != 1 {
		t.Fatalf("records = %v", h.Records)
	}
}

func TestLoadSkipsMalformedLinesAndMissingFile(t *testing.T) {
	dir := t.TempDir()
	if h, err := Load(filepath.Join(dir, "none.jsonl")); err != nil || len(h.Records) != 0 {
		t.Fatalf("missing file: %v %v", h, err)
	}
	p := filepath.Join(dir, FileName)
	data := "not json\n{\"type\":\"url\",\"value\":\"https://a.example.com\",\"status\":\"new\"}\n{\"type\":\"\"}\n"
	if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	h, err := Load(p)
	if err != nil || len(h.Records) != 1 {
		t.Fatalf("load = %v, %v", h, err)
	}
}

func TestAppendIsAtomicAndKeepsExistingLines(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "t", FileName)
	if err := Append(p, []Record{{Type: TypeURL, Value: "u1", Status: StatusNew}}); err != nil {
		t.Fatal(err)
	}
	if err := Append(p, []Record{{Type: TypeURL, Value: "u2", Status: StatusNew}}); err != nil {
		t.Fatal(err)
	}
	h, err := Load(p)
	if err != nil || len(h.Records) != 2 {
		t.Fatalf("records = %v, err %v", h, err)
	}
	entries, _ := os.ReadDir(filepath.Dir(p))
	if len(entries) != 1 {
		t.Fatalf("temp files left behind: %v", entries)
	}
}

func TestFocusKeepsNewChangedAndUnknownOnly(t *testing.T) {
	dir := t.TempDir()
	httpx := filepath.Join(dir, "httpx.jsonl")
	// unchanged.example.com identical, changed.example.com now has another title.
	lines := `{"url":"https://unchanged.example.com","host":"unchanged.example.com","status_code":200,"title":"U"}
{"url":"https://changed.example.com","host":"changed.example.com","status_code":200,"title":"NEW"}
`
	if err := os.WriteFile(httpx, []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}
	fp := func(title string) string {
		return HTTPFingerprint(report.HTTPService{StatusCode: 200, Title: title})
	}
	h := &History{Records: map[string]Record{}, runs: map[string]bool{}}
	for _, r := range []Record{
		{Type: TypeURL, Value: "https://unchanged.example.com", Status: StatusUnchanged, Fingerprint: fp("U")},
		{Type: TypeURL, Value: "https://changed.example.com", Status: StatusUnchanged, Fingerprint: fp("OLD")},
		{Type: TypeURL, Value: "https://gone.example.com", Status: StatusGone, Fingerprint: fp("G")},
		{Type: TypePath, Value: "https://unchanged.example.com/admin", Status: StatusUnchanged},
	} {
		h.Records[key(r.Type, r.Value)] = r
	}
	tests := []struct {
		name        string
		invalidated bool
		url         string
		want        bool
	}{
		{"unchanged url skipped", false, "https://unchanged.example.com", false},
		{"unchanged path skipped", false, "https://unchanged.example.com/admin", false},
		{"changed url kept", false, "https://changed.example.com", true},
		{"previously gone kept", false, "https://gone.example.com", true},
		{"unknown url kept", false, "https://new.example.com", true},
		{"invalidated keeps everything", true, "https://unchanged.example.com", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := NewFocus(h, tt.invalidated, httpx)
			if got := f.Keep(tt.url); got != tt.want {
				t.Fatalf("Keep(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
	if NewFocus(h, false, httpx).Digest() == NewFocus(h, true, httpx).Digest() {
		t.Error("digest must differ when the cache is invalidated")
	}
}
