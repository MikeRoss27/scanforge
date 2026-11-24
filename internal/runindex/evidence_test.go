package runindex

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const evRunID = "example.com/2026-02-02_00-00-00"

func writeEvidenceRun(t *testing.T) string {
	t.Helper()
	ws := t.TempDir()
	dir := filepath.Join(ws, "example.com", "2026-02-02_00-00-00")
	if err := os.MkdirAll(filepath.Join(dir, "00_meta"), 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(rel, body string) {
		if err := os.WriteFile(filepath.Join(dir, rel), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("00_meta/manifest.json", `{"id":"2026-02-02_00-00-00","target":"example.com","profile":"web","started_at":"2026-02-02T00:00:00Z","status":"completed","outputs":{}}`)
	write("report.json", `{"target":"example.com","profile":"web","status":"completed","assets":{"www.example.com":{"name":"www.example.com","vulnerabilities":[
{"source":"jssecrets","template_id":"aws-key","title":"AWS key","severity":"high","matched_at":"https://www.example.com/app.js","evidence":"AKIAIOSFODNN7EXAMPLE",
 "provenance":{"module":"jssecrets","tool":"scanforge","tool_version":"dev"},"status":"potential","confidence":"medium",
 "evidence_items":[{"kind":"static-match","summary":"s","artifact":"06_vulns/js-secrets.jsonl","excerpt":"AKIAIOSFODNN7EXAMPLE","verified_by":"pattern matched statically"}]},
{"source":"httpcheck","template_id":"missing-csp","title":"CSP","severity":"low","matched_at":"https://www.example.com/","status":"validated","confidence":"high"},
{"source":"nuclei","template_id":"legacy","title":"Old report entry","severity":"low","matched_at":"https://www.example.com/x"}]}}}`)
	return ws
}

func TestFindingsFilterByStatusAndConfidence(t *testing.T) {
	idx := New(writeEvidenceRun(t))
	tests := []struct {
		name   string
		filter FindingFilter
		want   int
	}{
		{"no filter", FindingFilter{}, 3},
		{"validated", FindingFilter{Status: "validated"}, 1},
		{"potential", FindingFilter{Status: "potential"}, 1},
		{"case-insensitive", FindingFilter{Status: "POTENTIAL"}, 1},
		{"version-match has none", FindingFilter{Status: "version-match"}, 0},
		{"confidence high", FindingFilter{Confidence: "high"}, 1},
		{"status and confidence combine", FindingFilter{Status: "validated", Confidence: "medium"}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			page, err := idx.Findings(evRunID, tt.filter)
			if err != nil {
				t.Fatal(err)
			}
			if page.Total != tt.want {
				t.Errorf("total = %d, want %d", page.Total, tt.want)
			}
		})
	}
}

// TestGetEvidenceReturnsEvidenceItemsUnmasked: leaked target values stay in
// full in findings and evidence, while the operator's own credentials are
// scrubbed from anything served.
func TestGetEvidenceReturnsEvidenceItemsUnmasked(t *testing.T) {
	idx := New(writeEvidenceRun(t), "operator-secret-value-1")
	page, err := idx.Findings(evRunID, FindingFilter{Source: "jssecrets"})
	if err != nil || len(page.Findings) != 1 {
		t.Fatalf("findings: %v %+v", err, page)
	}
	ev, err := idx.Evidence(evRunID, string(page.Findings[0].ID), "", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	out, err := idx.Encode(ev, evRunID)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{"AKIAIOSFODNN7EXAMPLE", `"evidence_items"`, `"verified_by"`, `"status": "potential"`, `"provenance"`} {
		if !strings.Contains(s, want) {
			t.Errorf("evidence output lacks %s: %s", want, s)
		}
	}
}
