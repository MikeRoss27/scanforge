package report

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCompareReportsAssets(t *testing.T) {
	before := NewReport("example.com", "recon")
	before.GetOrCreateAsset("a.example.com")
	before.GetOrCreateAsset("gone.example.com")

	after := NewReport("example.com", "recon")
	after.GetOrCreateAsset("a.example.com")
	after.GetOrCreateAsset("new.example.com")

	delta := CompareReports(before, after)
	if got := strings.Join(delta.AddedAssets, ","); got != "new.example.com" {
		t.Fatalf("AddedAssets = %q", got)
	}
	if got := strings.Join(delta.RemovedAssets, ","); got != "gone.example.com" {
		t.Fatalf("RemovedAssets = %q", got)
	}
}

func TestCompareReportsPorts(t *testing.T) {
	before := NewReport("example.com", "ports")
	asset := before.GetOrCreateAsset("a.example.com")
	asset.Ports = map[int]*Port{80: {Number: 80, Protocol: "tcp"}, 443: {Number: 443, Protocol: "tcp"}}

	after := NewReport("example.com", "ports")
	asset = after.GetOrCreateAsset("a.example.com")
	asset.Ports = map[int]*Port{80: {Number: 80, Protocol: "tcp"}, 8080: {Number: 8080, Protocol: "tcp"}}

	delta := CompareReports(before, after)
	if len(delta.AddedPorts) != 1 || delta.AddedPorts[0].Number != 8080 {
		t.Fatalf("AddedPorts = %+v", delta.AddedPorts)
	}
	if len(delta.RemovedPorts) != 1 || delta.RemovedPorts[0].Number != 443 {
		t.Fatalf("RemovedPorts = %+v", delta.RemovedPorts)
	}
}

func TestCompareReportsVulnerabilities(t *testing.T) {
	vuln := func(source, id, title, matched string) *Vulnerability {
		return &Vulnerability{Source: source, TemplateID: id, Title: title, MatchedAt: matched}
	}

	before := NewReport("example.com", "web")
	asset := before.GetOrCreateAsset("a.example.com")
	asset.Vulnerabilities = append(asset.Vulnerabilities,
		vuln("techcve", "CVE-2020-1", "Fixed issue", "a.example.com"))

	after := NewReport("example.com", "web")
	asset = after.GetOrCreateAsset("a.example.com")
	asset.Vulnerabilities = append(asset.Vulnerabilities,
		vuln("techcve", "CVE-2020-2", "New issue", "a.example.com"))

	delta := CompareReports(before, after)
	if len(delta.AddedVulns) != 1 || delta.AddedVulns[0].TemplateID != "CVE-2020-2" {
		t.Fatalf("AddedVulns = %+v", delta.AddedVulns)
	}
	if len(delta.FixedVulns) != 1 || delta.FixedVulns[0].TemplateID != "CVE-2020-1" {
		t.Fatalf("FixedVulns = %+v", delta.FixedVulns)
	}
	if delta.Empty() {
		t.Fatal("delta must not be empty")
	}
}

func TestCompareReportsEmpty(t *testing.T) {
	before := NewReport("example.com", "web")
	before.GetOrCreateAsset("a.example.com")
	after := NewReport("example.com", "web")
	after.GetOrCreateAsset("a.example.com")

	delta := CompareReports(before, after)
	if !delta.Empty() {
		t.Fatalf("identical runs must produce an empty delta: %+v", delta)
	}
}

func TestRunDeltaJSONRoundTrip(t *testing.T) {
	delta := RunDelta{
		AddedAssets: []string{"new.example.com"},
		AddedVulns: []VulnKey{
			{Source: "nuclei", TemplateID: "cve-1", Title: "Issue", MatchedAt: "https://a.example.com"},
		},
	}
	data, err := json.Marshal(delta)
	if err != nil {
		t.Fatal(err)
	}
	var back RunDelta
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if len(back.AddedAssets) != 1 || len(back.AddedVulns) != 1 || back.AddedVulns[0].TemplateID != "cve-1" {
		t.Fatalf("round trip mismatch: %+v", back)
	}
}

func TestFormatRunDelta(t *testing.T) {
	delta := RunDelta{
		AddedAssets: []string{"new.example.com"},
		AddedPorts:  []PortKey{{Host: "a.example.com", Number: 8080, Protocol: "tcp"}},
		AddedVulns:  []VulnKey{{Source: "techcve", TemplateID: "CVE-1", Title: "Issue", MatchedAt: "a.example.com"}},
		FixedVulns:  []VulnKey{{Source: "techcve", TemplateID: "CVE-0", Title: "Old", MatchedAt: "a.example.com"}},
	}
	out := FormatRunDelta(delta)
	for _, want := range []string{
		"new.example.com",
		"a.example.com:8080/tcp",
		"[CVE-1] Issue",
		"[CVE-0] Old",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output misses %q:\n%s", want, out)
		}
	}
}
