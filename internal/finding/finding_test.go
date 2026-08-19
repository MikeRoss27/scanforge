package finding

import (
	"testing"

	"github.com/MikeRoss27/scanforge/internal/report"
)

func TestNormalizeSeverity(t *testing.T) {
	cases := map[string]Severity{
		"critical":      SevCritical,
		"CRITICAL":      SevCritical,
		"high":          SevHigh,
		"medium":        SevMedium,
		"moderate":      SevMedium,
		"low":           SevLow,
		"info":          SevInfo,
		"informational": SevInfo,
		"weird-label":   SevInfo,
		"":              SevInfo,
	}
	for input, want := range cases {
		if got := NormalizeSeverity(input); got != want {
			t.Errorf("NormalizeSeverity(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestFingerprintDeterministic(t *testing.T) {
	f := Finding{
		Source: "nuclei", TemplateID: "cve-2026-0001", Asset: "example.com",
		MatchedAt: "https://example.com/admin", Evidence: "HTTP/1.1 200 OK",
	}
	first := f.Fingerprint()
	second := f.Fingerprint()
	if first != second {
		t.Fatalf("fingerprint not stable: %q vs %q", first, second)
	}
	if len(first) != 18 || first[:2] != "F-" {
		t.Fatalf("unexpected fingerprint format %q", first)
	}

	other := f
	other.Evidence = "HTTP/1.1 500 Internal Server Error"
	if other.Fingerprint() == first {
		t.Fatalf("fingerprint must differ when evidence differs")
	}
}

func TestFromReportProjectsVulnerabilities(t *testing.T) {
	rep := report.NewReport("example.com", "web")
	asset := rep.GetOrCreateAsset("example.com")
	asset.Vulnerabilities = append(asset.Vulnerabilities,
		&report.Vulnerability{
			Source: "nuclei", TemplateID: "t-1", Title: "XSS", Severity: "high",
			MatchedAt: "https://example.com/search", Evidence: "reflected",
			CVEs: []string{"CVE-2026-0001"}, CVSS: 8.1, EPSS: 0.5, KEV: true,
		},
		&report.Vulnerability{
			Source: "techcve", TemplateID: "CVE-2026-0002", Title: "RCE",
			Severity: "critical", MatchedAt: "example.com",
		},
	)
	rep.JSVerified = append(rep.JSVerified, report.VerifiedFinding{
		URL: "https://example.com/app.js", Kind: "api_key", Pattern: "sk-[a-z]+",
		Severity: "medium", Evidence: "sk-abc123",
	})

	findings := FromReport(rep)
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}

	vuln := findings[0]
	if vuln.Kind != "vulnerability" || vuln.Asset != "example.com" {
		t.Errorf("unexpected vuln projection: %+v", vuln)
	}
	if vuln.URL != "https://example.com/search" {
		t.Errorf("URL should be the http(s) matched_at, got %q", vuln.URL)
	}
	if vuln.Severity != SevHigh || vuln.CVSS != 8.1 || !vuln.KEV {
		t.Errorf("vuln fields not projected: %+v", vuln)
	}
	if vuln.ID == "" {
		t.Error("projected finding missing ID")
	}

	techcve := findings[1]
	if techcve.URL != "" {
		t.Errorf("non-URL matched_at must not become a URL, got %q", techcve.URL)
	}

	secret := findings[2]
	if secret.Kind != "verified_secret" || secret.Asset != "example.com" {
		t.Errorf("unexpected secret projection: %+v", secret)
	}
}

func TestFromReportDeterministicOrder(t *testing.T) {
	rep := report.NewReport("example.com", "web")
	rep.GetOrCreateAsset("b.example.com").Vulnerabilities = append(
		rep.GetOrCreateAsset("b.example.com").Vulnerabilities,
		&report.Vulnerability{Source: "nuclei", TemplateID: "t", Title: "B", MatchedAt: "b.example.com"})
	rep.GetOrCreateAsset("a.example.com").Vulnerabilities = append(
		rep.GetOrCreateAsset("a.example.com").Vulnerabilities,
		&report.Vulnerability{Source: "nuclei", TemplateID: "t", Title: "A", MatchedAt: "a.example.com"})

	first := FromReport(rep)
	second := FromReport(rep)
	if len(first) != 2 || len(second) != 2 {
		t.Fatalf("expected 2 findings, got %d and %d", len(first), len(second))
	}
	if first[0].Asset != "a.example.com" || second[0].Asset != "a.example.com" {
		t.Errorf("assets must be visited in sorted order (got %q and %q)", first[0].Asset, second[0].Asset)
	}
}

func TestBuildRelations(t *testing.T) {
	mk := func(source, template, asset, url string, cves []string) Finding {
		f := Finding{
			Kind: "vulnerability", Asset: asset, Source: source,
			TemplateID: template, URL: url, CVEs: cves, MatchedAt: url,
		}
		f.ID = f.Fingerprint()
		return f
	}

	findings := []Finding{
		mk("nuclei", "t-1", "a.com", "https://a.com/x", nil),
		mk("nuclei", "t-1", "a.com", "https://a.com/y", nil), // duplicate of first
		mk("nuclei", "t-2", "a.com", "https://a.com/z", []string{"CVE-2026-0001"}),
		mk("techcve", "CVE-2026-0001", "b.com", "", []string{"CVE-2026-0001"}), // shares CVE with third
		mk("nuclei", "t-3", "c.com", "https://c.com", nil),                     // isolated
	}

	relations := BuildRelations(findings)
	if len(relations) != 4 {
		t.Fatalf("expected 4 relations, got %d: %+v", len(relations), relations)
	}

	byType := map[RelationType]int{}
	for _, rel := range relations {
		byType[rel.Type]++
		if rel.From >= rel.To {
			t.Errorf("relation not canonical (From %q >= To %q)", rel.From, rel.To)
		}
	}
	if byType[RelDuplicate] != 1 {
		t.Errorf("expected 1 duplicate relation, got %d", byType[RelDuplicate])
	}
	if byType[RelSameCVE] != 1 {
		t.Errorf("expected 1 same_cve relation, got %d", byType[RelSameCVE])
	}
	if byType[RelSameAsset] != 2 {
		t.Errorf("expected 2 same_asset relations, got %d", byType[RelSameAsset])
	}
}

func TestBuildRelationsDeterministic(t *testing.T) {
	mk := func(source, template, asset string) Finding {
		f := Finding{Kind: "vulnerability", Asset: asset, Source: source, TemplateID: template}
		f.ID = f.Fingerprint()
		return f
	}
	findings := []Finding{
		mk("nuclei", "t-1", "a.com"),
		mk("nuclei", "t-1", "a.com"),
		mk("nuclei", "t-2", "b.com"),
	}
	first := BuildRelations(findings)
	second := BuildRelations(findings)
	if len(first) != len(second) {
		t.Fatalf("relation count not stable")
	}
	for i := range first {
		if first[i] != second[i] {
			t.Errorf("relations not deterministic at %d: %+v vs %+v", i, first[i], second[i])
		}
	}
}
