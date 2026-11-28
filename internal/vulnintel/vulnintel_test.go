package vulnintel

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

type fakeFeeds struct {
	t        *testing.T
	apiKeys  []string
	nvdCalls int
	queries  []string
	throttle bool // first NVD request answers 429
}

func (f *fakeFeeds) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/nvd", func(w http.ResponseWriter, r *http.Request) {
		f.nvdCalls++
		f.apiKeys = append(f.apiKeys, r.Header.Get("apiKey"))
		f.queries = append(f.queries, r.URL.RawQuery)
		if f.throttle && f.nvdCalls == 1 {
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		name := "nvd_page1.json"
		if r.URL.Query().Get("startIndex") == "2" {
			name = "nvd_page2.json"
		}
		_, _ = w.Write(fixture(f.t, name))
	})
	mux.HandleFunc("/kev", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(fixture(f.t, "kev.json"))
	})
	mux.HandleFunc("/epss", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(fixture(f.t, "epss.csv"))
	})
	mux.HandleFunc("/epss.gz", func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		_, _ = gz.Write(fixture(f.t, "epss.csv"))
		_ = gz.Close()
		_, _ = w.Write(buf.Bytes())
	})
	return mux
}

func newClient(srv *httptest.Server, key string, sleeps *[]time.Duration) *Client {
	return &Client{
		HTTP:    srv.Client(),
		NVDURL:  srv.URL + "/nvd",
		KEVURL:  srv.URL + "/kev",
		EPSSURL: srv.URL + "/epss.gz",
		NVDKey:  key,
		Now:     func() time.Time { return time.Date(2025, 1, 16, 0, 0, 0, 0, time.UTC) },
		Sleep: func(_ context.Context, d time.Duration) error {
			*sleeps = append(*sleeps, d)
			return nil
		},
	}
}

func updatedStore(t *testing.T) *Store {
	t.Helper()
	feeds := &fakeFeeds{t: t}
	srv := httptest.NewServer(feeds.handler())
	t.Cleanup(srv.Close)
	var sleeps []time.Duration
	store := &Store{Dir: filepath.Join(t.TempDir(), "intel")}
	if _, err := Update(context.Background(), store, newClient(srv, "", &sleeps), nil); err != nil {
		t.Fatalf("Update() error = %v", err)
	}
	return store
}

func TestUpdateStoresRecordsWithProvenance(t *testing.T) {
	store := updatedStore(t)
	meta, err := store.ReadMeta()
	if err != nil {
		t.Fatal(err)
	}
	if got := meta.SortedSources(); strings.Join(got, ",") != "epss,kev,nvd" {
		t.Fatalf("sources = %v", got)
	}
	if meta.Sources["nvd"].Records != 3 || meta.Sources["kev"].Records != 2 || meta.Sources["epss"].Records != 3 {
		t.Fatalf("unexpected record counts: %+v", meta.Sources)
	}
	if v := meta.Sources["kev"].FeedVersion; v != "2025.01.14@2025-01-14T15:00:00.000Z" {
		t.Fatalf("kev feed version = %q", v)
	}
	if v := meta.Sources["epss"].FeedVersion; v != "v2025.03.14@2025-01-15T12:55:00Z" {
		t.Fatalf("epss feed version = %q", v)
	}

	var cves []CVERecord
	if err := readAll(store, SourceNVD, func(r CVERecord) { cves = append(cves, r) }); err != nil {
		t.Fatal(err)
	}
	for _, c := range cves {
		if c.Source != "nvd" || c.FetchedAt.IsZero() || c.FeedVersion == "" {
			t.Fatalf("record %s lacks provenance: %+v", c.ID, c.Provenance)
		}
	}
	tomcat := cves[0]
	if tomcat.ID != "CVE-2023-0001" || tomcat.Description != "Tomcat request smuggling example." ||
		tomcat.CVSS != 9.8 || tomcat.Severity != "critical" {
		t.Fatalf("bad normalization: %+v", tomcat)
	}
	if len(tomcat.Matches) != 1 || tomcat.Matches[0].StartIncl != "9.0.0" || tomcat.Matches[0].EndExcl != "9.0.81" {
		t.Fatalf("non-vulnerable CPE must be skipped and range kept: %+v", tomcat.Matches)
	}
	if cves[1].Severity != "medium" {
		t.Fatalf("v2 severity fallback failed: %+v", cves[1])
	}
}

func TestNVDRateLimitAndAPIKey(t *testing.T) {
	for _, tc := range []struct {
		key      string
		interval time.Duration
	}{{"", 6500 * time.Millisecond}, {"secret-key", 700 * time.Millisecond}} {
		feeds := &fakeFeeds{t: t, throttle: true}
		srv := httptest.NewServer(feeds.handler())
		var sleeps []time.Duration
		var progress []string
		c := newClient(srv, tc.key, &sleeps)
		c.Progress = func(f string, a ...any) { progress = append(progress, f) }
		recs, _, err := c.FetchNVD(context.Background(), time.Time{})
		srv.Close()
		if err != nil || len(recs) != 3 {
			t.Fatalf("FetchNVD() = %d recs, err %v", len(recs), err)
		}
		// 429 honors Retry-After (7s), then one pause between the two pages.
		if len(sleeps) != 2 || sleeps[0] != 7*time.Second || sleeps[1] != tc.interval {
			t.Fatalf("key=%q sleeps = %v, want [7s %v]", tc.key, sleeps, tc.interval)
		}
		for _, k := range feeds.apiKeys {
			if k != tc.key {
				t.Fatalf("apiKey header = %q, want %q", k, tc.key)
			}
		}
		for _, q := range feeds.queries {
			if strings.Contains(q, "secret-key") {
				t.Fatal("API key leaked into URL")
			}
		}
		for _, p := range progress {
			if strings.Contains(p, "secret-key") {
				t.Fatal("API key leaked into progress output")
			}
		}
	}
}

func TestNVDIncrementalUpdateMerges(t *testing.T) {
	store := updatedStore(t)
	feeds := &fakeFeeds{t: t}
	srv := httptest.NewServer(feeds.handler())
	defer srv.Close()
	var sleeps []time.Duration
	client := newClient(srv, "", &sleeps)
	client.Now = func() time.Time { return time.Date(2025, 1, 20, 0, 0, 0, 0, time.UTC) }
	if _, err := Update(context.Background(), store, client, []string{"nvd"}); err != nil {
		t.Fatal(err)
	}
	if len(feeds.queries) == 0 || !strings.Contains(feeds.queries[0], "lastModStartDate") {
		t.Fatalf("expected incremental query, got %v", feeds.queries)
	}
	meta, _ := store.ReadMeta()
	if meta.Sources["nvd"].Records != 3 {
		t.Fatalf("merge should dedupe by ID, got %d", meta.Sources["nvd"].Records)
	}
}

func TestUpdateRejectsUnknownSource(t *testing.T) {
	_, err := Update(context.Background(), &Store{Dir: t.TempDir()}, &Client{}, []string{"bogus"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestParseEPSSPlainAndGzip(t *testing.T) {
	recs, version, err := ParseEPSS(fixture(t, "epss.csv"), time.Now())
	if err != nil || len(recs) != 3 {
		t.Fatalf("ParseEPSS() = %d, %v", len(recs), err)
	}
	if recs[2].CVEID != "CVE-2023-0002" || recs[0].Score != 0.91 || recs[0].Percentile != 0.99 {
		t.Fatalf("bad rows: %+v", recs)
	}
	if version != "v2025.03.14@2025-01-15T12:55:00Z" || recs[0].ScoreDate != "2025-01-15T12:55:00Z" {
		t.Fatalf("bad version %q", version)
	}
	if _, _, err := ParseEPSS(nil, time.Now()); err == nil {
		t.Fatal("empty input must fail")
	}
}

func TestMatchQualities(t *testing.T) {
	db, err := Load(updatedStore(t))
	if err != nil {
		t.Fatal(err)
	}
	find := func(cands []Candidate, id string) *Candidate {
		for i := range cands {
			if cands[i].CVEID == id {
				return &cands[i]
			}
		}
		return nil
	}

	cases := []struct {
		name      string
		q         Query
		cve       string
		quality   string // "" means must not be returned
		confirmed bool
	}{
		{"cpe in range", Query{Product: "Apache Tomcat", Version: "9.0.79", CPE: "cpe:2.3:a:apache:tomcat:9.0.79:*:*:*:*:*:*:*"}, "CVE-2023-0001", QualityExactCPERange, true},
		{"cpe version from cpe", Query{CPE: "cpe:2.3:a:apache:tomcat:9.0.79:*:*:*:*:*:*:*"}, "CVE-2023-0001", QualityExactCPERange, true},
		{"cpe patched", Query{Product: "tomcat", Version: "9.0.81", CPE: "cpe:2.3:a:apache:tomcat:9.0.81:*:*:*:*:*:*:*"}, "CVE-2023-0001", "", false},
		{"name in range", Query{Product: "Apache Tomcat", Version: "9.0.79"}, "CVE-2023-0001", QualityVersionRange, true},
		{"name patched", Query{Product: "tomcat", Version: "10.1.0"}, "CVE-2023-0001", "", false},
		{"inclusive end", Query{Product: "apache", Version: "2.4.38"}, "CVE-2019-0003", QualityVersionRange, true},
		{"past inclusive end", Query{Product: "apache", Version: "2.4.39"}, "CVE-2019-0003", "", false},
		{"exact cpe version", Query{Product: "apache", Version: "2.2.34"}, "CVE-2019-0003", QualityVersionRange, true},
		{"all versions is name-only", Query{Product: "nginx", Version: "1.25.3"}, "CVE-2023-0002", QualityNameOnly, false},
		{"unknown version is name-only", Query{Product: "tomcat"}, "CVE-2023-0001", QualityNameOnly, false},
		{"similar name never confirmed", Query{Product: "tomcat-embed", Version: "9.0.79"}, "CVE-2023-0001", QualityNameOnly, false},
		{"same product other vendor", Query{Product: "tomcat", Version: "9.0.79", CPE: "cpe:2.3:a:evilcorp:tomcat:9.0.79:*:*:*:*:*:*:*"}, "CVE-2023-0001", QualityNameOnly, false},
		{"unrelated product", Query{Product: "wordpress", Version: "6.3"}, "CVE-2023-0001", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := find(db.Match(tc.q), tc.cve)
			if tc.quality == "" {
				if got != nil {
					t.Fatalf("unexpected candidate %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatalf("missing candidate %s", tc.cve)
			}
			if got.Quality != tc.quality || got.Confirmed != tc.confirmed {
				t.Fatalf("got quality=%s confirmed=%v, want %s/%v", got.Quality, got.Confirmed, tc.quality, tc.confirmed)
			}
			if got.Source != "nvd" || got.FetchedAt.IsZero() {
				t.Fatalf("candidate lost provenance: %+v", got.Provenance)
			}
		})
	}
}

func TestMatchEnrichesAndSorts(t *testing.T) {
	db, err := Load(updatedStore(t))
	if err != nil {
		t.Fatal(err)
	}
	got := db.Match(Query{Product: "apache", Version: "2.4.30"})
	if len(got) != 1 || !got[0].KEV || got[0].EPSS != 0.002 || got[0].EPSSPercentile != 0.4 || got[0].CVSS != 7.8 {
		t.Fatalf("enrichment failed: %+v", got)
	}
	// name-only candidates sort after confirmed ones.
	all := db.Match(Query{Product: "tomcat", Version: "9.0.79"})
	for i := 1; i < len(all); i++ {
		if qualityRank(all[i-1].Quality) > qualityRank(all[i].Quality) {
			t.Fatalf("not sorted: %+v", all)
		}
	}
}

func TestMissingCacheIsEmpty(t *testing.T) {
	t.Setenv(EnvDir, filepath.Join(t.TempDir(), "none"))
	if OpenIfPresent() != nil {
		t.Fatal("OpenIfPresent must be nil without cache")
	}
	db, err := Load(&Store{Dir: t.TempDir()})
	if err != nil || len(db.Match(Query{Product: "nginx", Version: "1"})) != 0 {
		t.Fatalf("empty cache must match nothing: %v", err)
	}
}

// A single malformed line in the NVD or KEV cache (partial write, truncated
// download, bit rot) must not discard every other record in that ~86 MB
// feed, and must not make OpenIfPresent fall back to nil (silently running
// techcve/wpcve with zero CVE intel and no warning).
func TestLoadSkipsCorruptLineInsteadOfFailingWholeCache(t *testing.T) {
	dir := t.TempDir()
	good := `{"id":"CVE-2099-0001","matches":[{"criteria":"cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*","vendor":"f5","product":"nginx"}]}`
	nvd := strings.Join([]string{
		good,
		`{"id":"CVE-2099-0002", this is not valid json`,
		good,
	}, "\n")
	if err := os.WriteFile(filepath.Join(dir, "nvd.jsonl"), []byte(nvd), 0o644); err != nil {
		t.Fatal(err)
	}
	kev := strings.Join([]string{
		`not json at all`,
		`{"cve_id":"CVE-2099-0001"}`,
	}, "\n")
	if err := os.WriteFile(filepath.Join(dir, "kev.jsonl"), []byte(kev), 0o644); err != nil {
		t.Fatal(err)
	}
	meta := `{"sources":{"nvd":{"source":"nvd","records":2},"kev":{"source":"kev","records":1}}}`
	if err := os.WriteFile(filepath.Join(dir, "meta.json"), []byte(meta), 0o644); err != nil {
		t.Fatal(err)
	}

	db, err := Load(&Store{Dir: dir})
	if err != nil {
		t.Fatalf("Load must tolerate a corrupt line, got: %v", err)
	}
	cands := db.Match(Query{Product: "nginx", CPE: "cpe:2.3:a:f5:nginx:1.0:*:*:*:*:*:*:*"})
	if len(cands) != 1 || cands[0].CVEID != "CVE-2099-0001" {
		t.Fatalf("good records must survive a corrupt sibling line: %+v", cands)
	}
	if !cands[0].KEV {
		t.Fatalf("KEV flag must survive a corrupt sibling line in kev.jsonl: %+v", cands[0])
	}

	t.Setenv(EnvDir, dir)
	if OpenIfPresent() == nil {
		t.Fatal("OpenIfPresent must not fall back to nil over one corrupt line")
	}
}

func TestCacheFreshness(t *testing.T) {
	writeMeta := func(t *testing.T, dir string, sources map[string]SourceMeta) {
		t.Helper()
		m := Meta{Sources: sources}
		data, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "meta.json"), data, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "nvd.jsonl"), []byte(""), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("no cache directory at all", func(t *testing.T) {
		t.Setenv(EnvDir, filepath.Join(t.TempDir(), "none"))
		if _, ok := CacheFreshness(); ok {
			t.Fatal("expected ok=false when the cache directory doesn't exist")
		}
	})

	t.Run("cache directory exists but meta.json has no sources", func(t *testing.T) {
		dir := t.TempDir()
		writeMeta(t, dir, map[string]SourceMeta{})
		t.Setenv(EnvDir, dir)
		if _, ok := CacheFreshness(); ok {
			t.Fatal("expected ok=false when meta.json records no sources")
		}
	})

	t.Run("fresh cache", func(t *testing.T) {
		dir := t.TempDir()
		writeMeta(t, dir, map[string]SourceMeta{
			"nvd": {Source: "nvd", FetchedAt: time.Now().Add(-time.Hour)},
			"kev": {Source: "kev", FetchedAt: time.Now().Add(-2 * time.Hour)},
		})
		t.Setenv(EnvDir, dir)
		age, ok := CacheFreshness()
		if !ok {
			t.Fatal("expected ok=true")
		}
		if age < 2*time.Hour || age > 3*time.Hour {
			t.Fatalf("expected age around the oldest source (~2h), got %v", age)
		}
	})

	t.Run("stale cache reports the oldest source's age", func(t *testing.T) {
		dir := t.TempDir()
		writeMeta(t, dir, map[string]SourceMeta{
			"nvd": {Source: "nvd", FetchedAt: time.Now().Add(-40 * 24 * time.Hour)},
			"kev": {Source: "kev", FetchedAt: time.Now().Add(-time.Hour)},
		})
		t.Setenv(EnvDir, dir)
		age, ok := CacheFreshness()
		if !ok {
			t.Fatal("expected ok=true")
		}
		if age <= MaxCacheAge {
			t.Fatalf("expected a stale age over MaxCacheAge (%v), got %v", MaxCacheAge, age)
		}
	})
}

func TestParseCPE(t *testing.T) {
	c, ok := ParseCPE(`cpe:2.3:a:vendor\:x:prod_1:1.2:*:*:*:*:*:*:*`)
	if !ok || c.Vendor != "vendor:x" || c.Product != "prod_1" || c.Version != "1.2" {
		t.Fatalf("ParseCPE = %+v %v", c, ok)
	}
	if _, ok := ParseCPE("not-a-cpe"); ok {
		t.Fatal("must reject garbage")
	}
}

func TestNVDKeyFromEnv(t *testing.T) {
	env := map[string]string{"NVD_API_KEY": "b"}
	get := func(k string) string { return env[k] }
	if NVDKeyFromEnv(get) != "b" {
		t.Fatal("fallback env var not used")
	}
	env["SCANFORGE_NVD_API_KEY"] = "a"
	if NVDKeyFromEnv(get) != "a" {
		t.Fatal("scanforge-specific var must win")
	}
}
