package techcve

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/vulnintel"
)

// TestMain isolates tests from any real ~/.cache/scanforge/vulnintel cache.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "techcve-intel-empty")
	if err != nil {
		panic(err)
	}
	_ = os.Setenv(vulnintel.EnvDir, dir)
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

type fakeIntel struct{ cands []vulnintel.Candidate }

func (f fakeIntel) Match(q vulnintel.Query) []vulnintel.Candidate {
	if q.Product == "" || q.Version == "" {
		return nil
	}
	return f.cands
}

func TestRunConsultsIntelAndKeepsBundledFallback(t *testing.T) {
	prov := vulnintel.Provenance{Source: "nvd", FetchedAt: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)}
	intel := fakeIntel{cands: []vulnintel.Candidate{
		{CVEID: "CVE-2099-0001", Description: "Confirmed example. More text.", CVSS: 9.1,
			Quality: vulnintel.QualityVersionRange, Confirmed: true, Provenance: prov},
		{CVEID: "CVE-2099-0002", Description: "Lead only.", Quality: vulnintel.QualityNameOnly, Provenance: prov},
	}}

	run := testRun(t)
	writeFile(t, run.Path("02_http", "httpx.jsonl"),
		`{"host":"example.com","tech":["jQuery:3.4.1"]}`+"\n")
	runCtx := modules.NewRunContext("example.com", "deep", false, run)
	if err := runCtx.AddArtifact("httpx_raw", modules.Artifact{Name: "httpx_raw", Type: "jsonl", Path: "02_http/httpx.jsonl"}); err != nil {
		t.Fatal(err)
	}
	if _, err := NewWithIntel(intel).Run(context.Background(), runCtx, nil); err != nil {
		t.Fatal(err)
	}

	byCVE := map[string]finding{}
	for _, f := range readFindings(t, run.Path(outputRel)) {
		byCVE[f.CVEID] = f
	}
	confirmed, ok := byCVE["CVE-2099-0001"]
	if !ok || confirmed.Confirmed == nil || !*confirmed.Confirmed || confirmed.Severity != "critical" ||
		confirmed.MatchQuality != vulnintel.QualityVersionRange || confirmed.IntelSource != "nvd" {
		t.Fatalf("bad confirmed intel finding: %+v", confirmed)
	}
	lead, ok := byCVE["CVE-2099-0002"]
	if !ok || lead.Confirmed == nil || *lead.Confirmed || lead.Severity != "info" || lead.Note == "" {
		t.Fatalf("name-only lead must be unconfirmed: %+v", lead)
	}
	if _, ok := byCVE["CVE-2020-11022"]; !ok {
		t.Fatalf("bundled dataset fallback finding missing: %+v", byCVE)
	}
}
