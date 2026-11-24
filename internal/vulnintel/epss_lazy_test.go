package vulnintel

import (
	"fmt"
	"os"
	"testing"
	"time"
)

// writeLargeEPSS writes n synthetic EPSS records (about 290 bytes each, like
// the real daily feed) plus one NVD record, so Load/Match can be timed on a
// cache comparable to the ~86 MB production one.
func writeLargeEPSS(tb testing.TB, n int) *Store {
	tb.Helper()
	store := &Store{Dir: tb.TempDir()}
	now := time.Date(2025, 1, 15, 0, 0, 0, 0, time.UTC)
	prov := Provenance{Source: SourceEPSS, FetchedAt: now, FeedVersion: "v2025.03.14@2025-01-15T12:55:00Z"}
	recs := make([]EPSSRecord, 0, n)
	for i := 0; i < n; i++ {
		recs = append(recs, EPSSRecord{
			CVEID: fmt.Sprintf("CVE-%d-%05d", 1999+i/20000, i%20000),
			Score: float64(i%1000) / 1000, Percentile: float64(i%997) / 997,
			ScoreDate: "2025-01-15T12:55:00Z", Provenance: prov,
		})
	}
	if err := replace(store, &SourceMeta{Source: SourceEPSS, FetchedAt: now, FeedVersion: prov.FeedVersion}, recs); err != nil {
		tb.Fatal(err)
	}
	nvd := []CVERecord{{
		ID: "CVE-1999-00042", Severity: "HIGH", CVSS: 7.5,
		Matches:    []CPEMatch{{Criteria: "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*", Vendor: "acme", Product: "widget", EndExcl: "2.0"}},
		Provenance: Provenance{Source: SourceNVD, FetchedAt: now},
	}}
	if err := replace(store, &SourceMeta{Source: SourceNVD, FetchedAt: now}, nvd); err != nil {
		tb.Fatal(err)
	}
	return store
}

func TestEPSSLazyLookupOnLargeCache(t *testing.T) {
	store := writeLargeEPSS(t, 30000)
	db, err := Load(store)
	if err != nil {
		t.Fatal(err)
	}
	if db.epssIdx != nil {
		t.Fatal("Load must not index or parse the EPSS cache")
	}
	got := db.Match(Query{Product: "widget", Version: "1.0"})
	if len(got) != 1 || got[0].CVEID != "CVE-1999-00042" || got[0].EPSS != 0.042 {
		t.Fatalf("Match() = %+v", got)
	}
	recs := db.epssFor([]string{"CVE-1999-00042", "CVE-1999-NOPE"})
	rec, ok := recs["CVE-1999-00042"]
	if !ok || rec.Score != 0.042 || rec.ScoreDate != "2025-01-15T12:55:00Z" {
		t.Fatalf("epssFor lookup = %+v ok=%v", rec, ok)
	}
	if _, ok := recs["CVE-1999-NOPE"]; ok {
		t.Fatal("unknown CVE must have no EPSS record")
	}
}

func TestEPSSLastDuplicateWinsAndMissingFileIsEmpty(t *testing.T) {
	store := &Store{Dir: t.TempDir()}
	line := func(score string) string {
		return `{"cve_id":"CVE-2020-0001","epss":` + score + `,"percentile":0.5,"source":"epss","fetched_at":"2025-01-15T00:00:00Z"}` + "\n"
	}
	if err := os.WriteFile(store.file(SourceEPSS), []byte(line("0.1")+"\n"+line("0.9")), 0o644); err != nil {
		t.Fatal(err)
	}
	db := &DB{epssStore: store}
	if got := db.epssFor([]string{"CVE-2020-0001"})["CVE-2020-0001"]; got.Score != 0.9 {
		t.Fatalf("duplicate resolution = %+v", got)
	}
	empty := &DB{epssStore: &Store{Dir: t.TempDir()}}
	if got := empty.epssFor([]string{"CVE-2020-0001"}); len(got) != 0 {
		t.Fatalf("missing cache = %+v", got)
	}
}

// BenchmarkLoadLargeEPSS measures what every techcve run pays up front.
func BenchmarkLoadLargeEPSS(b *testing.B) {
	store := writeLargeEPSS(b, 300000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Load(store); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkLoadAndMatchLargeEPSS includes the first (lazy) EPSS lookup.
func BenchmarkLoadAndMatchLargeEPSS(b *testing.B) {
	store := writeLargeEPSS(b, 300000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		db, err := Load(store)
		if err != nil {
			b.Fatal(err)
		}
		if got := db.Match(Query{Product: "widget", Version: "1.0"}); len(got) != 1 {
			b.Fatalf("Match() = %+v", got)
		}
	}
}
