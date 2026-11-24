package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/storage"
)

const evidenceRunDir = "testdata/evidence_run"

func evidenceManifest() *storage.RunManifest {
	return &storage.RunManifest{
		Target:  "example.com",
		Profile: "web",
		Status:  "completed",
		Outputs: map[string]string{
			"resolved_hosts": "01_subdomains/resolved.txt",
			"nuclei_raw":     "06_vulns/nuclei.jsonl",
			"cve_findings":   "06_vulns/cve-findings.jsonl",
			"js_secrets":     "06_vulns/js-secrets.jsonl",
			"js_verified":    "06_vulns/js-verified.jsonl",
			"http_checks":    "06_vulns/http-checks.jsonl",
			"wp_brute":       "06_vulns/wp-brute.jsonl",
			"wp_users":       "06_vulns/wp-users.jsonl",
		},
		ToolVersions: map[string]string{"nuclei": "v3.2.1"},
	}
}

func evidenceReport(t *testing.T) *Report {
	t.Helper()
	rep, err := GenerateReport(evidenceRunDir, evidenceManifest())
	if err != nil {
		t.Fatalf("GenerateReport: %v", err)
	}
	return rep
}

func findVuln(t *testing.T, rep *Report, host, templateID string) *Vulnerability {
	t.Helper()
	asset, ok := rep.Assets[host]
	if !ok {
		t.Fatalf("asset %q missing", host)
	}
	for _, v := range asset.Vulnerabilities {
		if v.TemplateID == templateID {
			return v
		}
	}
	t.Fatalf("no vulnerability %q on %q", templateID, host)
	return nil
}

// TestEvidenceStatusRules pins the status/confidence rule of every producer.
func TestEvidenceStatusRules(t *testing.T) {
	rep := evidenceReport(t)
	tests := []struct {
		name       string
		host       string
		template   string
		status     string
		confidence string
		module     string
		evKind     string
	}{
		{"nuclei match is only potential", "app.example.com", "exposed-admin-panel", StatusPotential, ConfidenceMedium, "nuclei", EvidenceTemplateMatch},
		{"techcve bundled dataset range", "app.example.com", "CVE-2021-23017", StatusVersionMatch, ConfidenceMedium, "techcve", EvidenceVersionMatch},
		{"techcve exact-cpe-range", "app.example.com", "CVE-2099-0001", StatusVersionMatch, ConfidenceHigh, "techcve", EvidenceVersionMatch},
		{"techcve version-range", "app.example.com", "CVE-2099-0002", StatusVersionMatch, ConfidenceMedium, "techcve", EvidenceVersionMatch},
		{"techcve name-only is a lead", "app.example.com", "CVE-2099-0003", StatusPotential, ConfidenceLow, "techcve", EvidenceVersionMatch},
		{"jssecrets secret stays potential", "app.example.com", "aws-access-key", StatusPotential, ConfidenceMedium, "jssecrets", EvidenceStaticMatch},
		{"jssecrets sink validated by executed replay", "app.example.com", "innerHTML", StatusValidated, ConfidenceHigh, "jssecrets", EvidenceStaticMatch},
		{"jssecrets sink with sink-reached replay is inconclusive", "app.example.com", "eval", StatusInconclusive, ConfidenceMedium, "jssecrets", EvidenceStaticMatch},
		{"jssecrets sink without usable replay stays potential", "app.example.com", "document.write", StatusPotential, ConfidenceLow, "jssecrets", EvidenceStaticMatch},
		{"httpcheck is observed directly", "app.example.com", "missing-csp", StatusValidated, ConfidenceHigh, "httpcheck", EvidenceObservation},
		{"wpbrute accepted login", "wp.example.com", "wp-credentials-validated", StatusValidated, ConfidenceHigh, "wpbrute", EvidenceAuth},
		{"wpusers disclosed login", "wp.example.com", "wp-user-enumerated", StatusValidated, ConfidenceHigh, "wpusers", EvidenceObservation},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := findVuln(t, rep, tt.host, tt.template)
			if v.Status != tt.status || v.Confidence != tt.confidence {
				t.Errorf("status/confidence = %q/%q, want %q/%q", v.Status, v.Confidence, tt.status, tt.confidence)
			}
			if !ValidStatus(v.Status) {
				t.Errorf("status %q is not canonical", v.Status)
			}
			if v.Provenance == nil || v.Provenance.Module != tt.module {
				t.Fatalf("provenance = %+v, want module %q", v.Provenance, tt.module)
			}
			if len(v.EvidenceItems) == 0 || v.EvidenceItems[0].Kind != tt.evKind {
				t.Fatalf("evidence items = %+v, want first kind %q", v.EvidenceItems, tt.evKind)
			}
			for _, ev := range v.EvidenceItems {
				if ev.VerifiedBy == "" || ev.Summary == "" {
					t.Errorf("evidence %+v lacks summary/verified_by", ev)
				}
				if filepath.IsAbs(ev.Artifact) || strings.Contains(ev.Artifact, "..") {
					t.Errorf("artifact %q must be run-relative", ev.Artifact)
				}
			}
		})
	}
}

func TestEvidenceNeverInventsVerification(t *testing.T) {
	rep := evidenceReport(t)
	// Every non-validated finding must say so in verified_by.
	for _, asset := range rep.Assets {
		for _, v := range asset.Vulnerabilities {
			if v.Status != StatusPotential {
				continue
			}
			joined := ""
			for _, ev := range v.EvidenceItems {
				joined += ev.VerifiedBy + "\n"
			}
			if !strings.Contains(joined, "not ") && !strings.Contains(joined, "nothing") && !strings.Contains(joined, "only") {
				t.Errorf("%s/%s is potential but verified_by does not state the limits: %q", asset.Name, v.TemplateID, joined)
			}
		}
	}
	// A sink-reached replay must not upgrade to validated, and the replay
	// evidence must say execution was not observed.
	v := findVuln(t, rep, "app.example.com", "eval")
	if last := v.EvidenceItems[len(v.EvidenceItems)-1]; last.Kind != EvidenceReplay || !strings.Contains(last.VerifiedBy, "not observed") {
		t.Errorf("replay evidence = %+v", last)
	}
}

func TestEvidenceProvenanceAndArtifacts(t *testing.T) {
	rep := evidenceReport(t)
	nuc := findVuln(t, rep, "app.example.com", "exposed-admin-panel")
	if nuc.Provenance.Tool != "nuclei" || nuc.Provenance.ToolVersion != "v3.2.1" {
		t.Errorf("nuclei provenance = %+v", nuc.Provenance)
	}
	if got := nuc.EvidenceItems[0].Artifact; got != "06_vulns/nuclei.jsonl" {
		t.Errorf("artifact = %q", got)
	}
	native := findVuln(t, rep, "app.example.com", "missing-csp")
	if native.Provenance.Tool != "scanforge" || native.Provenance.ToolVersion == "" {
		t.Errorf("native provenance = %+v", native.Provenance)
	}
	// Source stays the legacy module-name string.
	if nuc.Source != "nuclei" {
		t.Errorf("source = %q", nuc.Source)
	}
}

// TestEvidenceKeepsTargetSecretsInFull: values leaked by the target are bounty
// proof and must appear unmasked in the legacy evidence and the new items.
func TestEvidenceKeepsTargetSecretsInFull(t *testing.T) {
	rep := evidenceReport(t)
	v := findVuln(t, rep, "app.example.com", "aws-access-key")
	const secret = "AKIAIOSFODNN7EXAMPLE"
	if !strings.Contains(v.Evidence, secret) {
		t.Errorf("legacy evidence masked: %q", v.Evidence)
	}
	if !strings.Contains(v.EvidenceItems[0].Excerpt, secret) {
		t.Errorf("evidence excerpt masked: %q", v.EvidenceItems[0].Excerpt)
	}
	data, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), secret) {
		t.Error("secret missing from report.json")
	}
}

func TestEvidenceBackwardCompatibleJSON(t *testing.T) {
	legacy := `{"target":"t","profile":"p","started_at":"0001-01-01T00:00:00Z","completed_at":"0001-01-01T00:00:00Z","status":"completed","assets":{"a.t":{"name":"a.t","vulnerabilities":[{"source":"nuclei","template_id":"x","title":"X","severity":"low","matched_at":"https://a.t"}]}}}`
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"provenance", "evidence_items", "\"status\":\"potential", "confidence", "discovered_by"} {
		if strings.Contains(string(out), key) {
			t.Errorf("legacy report grew key %q: %s", key, out)
		}
	}
}

func TestEvidenceLine(t *testing.T) {
	rep := evidenceReport(t)
	line := EvidenceLine(findVuln(t, rep, "app.example.com", "exposed-admin-panel"))
	for _, want := range []string{"status potential", "confidence medium", "source nuclei v3.2.1", "template-match in 06_vulns/nuclei.jsonl", "verified:"} {
		if !strings.Contains(line, want) {
			t.Errorf("evidence line %q lacks %q", line, want)
		}
	}
	if got := EvidenceLine(&Vulnerability{Title: "legacy"}); got != "" {
		t.Errorf("legacy finding line = %q, want empty", got)
	}
}

func TestMarkdownIncludesEvidenceLine(t *testing.T) {
	rep := evidenceReport(t)
	path := filepath.Join(t.TempDir(), "report.md")
	if err := rep.WriteMarkdown(path); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	md := string(data)
	for _, want := range []string{"**Evidence:**", "status validated", "status version-match", "source nuclei v3.2.1"} {
		if !strings.Contains(md, want) {
			t.Errorf("report.md lacks %q", want)
		}
	}
}

func TestSARIFEvidenceMapping(t *testing.T) {
	rep := evidenceReport(t)
	path := filepath.Join(t.TempDir(), "r.sarif")
	if err := rep.WriteSARIF(path); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	var log struct {
		Runs []struct {
			Results []struct {
				RuleID     string                 `json:"ruleId"`
				Kind       string                 `json:"kind"`
				Rank       float64                `json:"rank"`
				Properties map[string]interface{} `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatal(err)
	}
	want := map[string]struct {
		kind string
		rank float64
		stat string
	}{
		"exposed-admin-panel": {"review", 50, StatusPotential},
		"missing-csp":         {"fail", 90, StatusValidated},
		"CVE-2099-0003":       {"review", 20, StatusPotential},
	}
	seen := 0
	for _, r := range log.Runs[0].Results {
		w, ok := want[r.RuleID]
		if !ok {
			continue
		}
		seen++
		if r.Kind != w.kind || r.Rank != w.rank || r.Properties["scanforge/status"] != w.stat {
			t.Errorf("%s: kind=%q rank=%v props=%v, want %+v", r.RuleID, r.Kind, r.Rank, r.Properties, w)
		}
		if _, ok := r.Properties["scanforge/evidence"]; !ok {
			t.Errorf("%s: no scanforge/evidence property", r.RuleID)
		}
	}
	if seen != len(want) {
		t.Errorf("matched %d results, want %d", seen, len(want))
	}
}

func TestSARIFLegacyFindingUnchanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "r.sarif")
	if err := vulnFixture().WriteSARIF(path); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	for _, key := range []string{`"kind"`, `"rank"`, `"properties"`} {
		if strings.Contains(string(data), key) {
			t.Errorf("legacy SARIF grew %s", key)
		}
	}
}

func TestDefectDojoEvidenceMapping(t *testing.T) {
	rep := evidenceReport(t)
	path := filepath.Join(t.TempDir(), "dd.json")
	if err := rep.WriteDefectDojo(path); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	var findings []defectDojoFinding
	if err := json.Unmarshal(data, &findings); err != nil {
		t.Fatal(err)
	}
	byTitle := map[string]defectDojoFinding{}
	for _, f := range findings {
		byTitle[f.Title] = f
	}
	validated := byTitle["Missing Content-Security-Policy header"]
	if !validated.Verified || validated.UnderReview {
		t.Errorf("validated finding: verified=%v under_review=%v", validated.Verified, validated.UnderReview)
	}
	potential := byTitle["Admin panel exposed"]
	if potential.Verified || !potential.UnderReview {
		t.Errorf("potential finding: verified=%v under_review=%v", potential.Verified, potential.UnderReview)
	}
	joined := strings.Join(potential.Tags, ",")
	for _, want := range []string{"panel", "status:potential", "confidence:medium"} {
		if !strings.Contains(joined, want) {
			t.Errorf("tags %q lack %q", joined, want)
		}
	}
	if !strings.Contains(potential.StepsToReproduce, "verified by:") {
		t.Errorf("steps = %q", potential.StepsToReproduce)
	}
}

// TestRecursiveFold covers part B: assets discovered by --recursive reach
// report.json, scope-filtered, and are marked.
func TestRecursiveFold(t *testing.T) {
	rep := evidenceReport(t)

	dev, ok := rep.Assets["dev.example.com"]
	if !ok {
		t.Fatalf("recursive asset dev.example.com missing; assets=%v", assetNames(rep))
	}
	if dev.DiscoveredBy != DiscoveredByRecursive {
		t.Errorf("DiscoveredBy = %q", dev.DiscoveredBy)
	}
	if len(dev.IPs) != 1 || dev.IPs[0] != "192.0.2.50" || len(dev.CNAMEs) != 1 {
		t.Errorf("dnsx enrichment not merged: %+v", dev)
	}
	if len(dev.HTTP) != 1 || dev.HTTP[0].URL != "https://dev.example.com" || len(dev.Technologies) != 1 {
		t.Errorf("httpx enrichment not merged: %+v", dev)
	}
	urls := map[string]bool{}
	for _, p := range dev.Paths {
		urls[p.URL] = true
	}
	if !urls["https://dev.example.com/api/v1/users"] || !urls["https://dev.example.com/app.js"] || len(urls) != 2 {
		t.Errorf("katana paths = %v", urls)
	}
	// Assets from the regular DAG are not relabelled.
	if rep.Assets["app.example.com"].DiscoveredBy != "" {
		t.Error("DAG asset marked as recursive")
	}
}

func TestRecursiveFoldDropsOutOfScope(t *testing.T) {
	rep := evidenceReport(t)
	for _, host := range []string{"evil.other.com", "stale.example.org", "cdn.other.com"} {
		if _, ok := rep.Assets[host]; ok {
			t.Errorf("out-of-scope asset %q leaked into the report", host)
		}
	}
	data, _ := json.Marshal(rep)
	for _, bad := range []string{"evil.other.com", "stale.example.org", "cdn.other.com", "198.51.100"} {
		if strings.Contains(string(data), bad) {
			t.Errorf("report.json mentions out-of-scope %q", bad)
		}
	}
}

func TestRecursiveFoldMissingDirIsNoop(t *testing.T) {
	rep := NewReport("example.com", "web")
	if err := foldRecursive(t.TempDir(), rep); err != nil {
		t.Fatalf("foldRecursive: %v", err)
	}
	if len(rep.Assets) != 0 {
		t.Errorf("assets = %v", assetNames(rep))
	}
}

func TestRecursiveFoldDeterministic(t *testing.T) {
	a, _ := json.Marshal(evidenceReport(t).Assets["dev.example.com"])
	b, _ := json.Marshal(evidenceReport(t).Assets["dev.example.com"])
	if string(a) != string(b) {
		t.Errorf("non-deterministic fold:\n%s\n%s", a, b)
	}
}

func assetNames(rep *Report) []string {
	var names []string
	for n := range rep.Assets {
		names = append(names, n)
	}
	return names
}
