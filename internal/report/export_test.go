package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func vulnFixture() *Report {
	r := NewReport("example.com", "web")
	asset := r.GetOrCreateAsset("a.example.com")
	asset.Vulnerabilities = append(asset.Vulnerabilities,
		&Vulnerability{
			Source:      "nuclei",
			TemplateID:  "cve-2021-1234",
			Title:       "Remote code execution",
			Description: "Critical RCE",
			Severity:    "critical",
			MatchedAt:   "https://a.example.com/admin",
			Tags:        []string{"rce"},
			CVEs:        []string{"CVE-2021-1234"},
			CWEs:        []string{"CWE-79"},
			References:  []string{"https://example.test/advisory"},
		},
		&Vulnerability{
			Source:     "httpcheck",
			TemplateID: "missing-hsts",
			Title:      "Missing HSTS",
			Severity:   "low",
			MatchedAt:  "https://a.example.com",
		})
	return r
}

func TestWriteSARIF(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.sarif")
	if err := vulnFixture().WriteSARIF(path); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var log struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name    string `json:"name"`
					Version string `json:"version"`
					Rules   []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID string `json:"ruleId"`
				Level  string `json:"level"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatal(err)
	}
	if log.Version != "2.1.0" {
		t.Fatalf("version = %q", log.Version)
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "ScanForge" {
		t.Fatalf("driver name = %q", run.Tool.Driver.Name)
	}
	if len(run.Tool.Driver.Rules) != 2 {
		t.Fatalf("rules = %d, want 2", len(run.Tool.Driver.Rules))
	}
	if len(run.Results) != 2 {
		t.Fatalf("results = %d, want 2", len(run.Results))
	}
	byRule := map[string]string{}
	for _, res := range run.Results {
		byRule[res.RuleID] = res.Level
	}
	if byRule["cve-2021-1234"] != "error" {
		t.Fatalf("critical mapped to %q, want error", byRule["cve-2021-1234"])
	}
	if byRule["missing-hsts"] != "note" {
		t.Fatalf("low mapped to %q, want note", byRule["missing-hsts"])
	}
}

func TestWriteDefectDojo(t *testing.T) {
	path := filepath.Join(t.TempDir(), "findings.json")
	if err := vulnFixture().WriteDefectDojo(path); err != nil {
		t.Fatalf("WriteDefectDojo: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var findings []struct {
		Title    string   `json:"title"`
		Severity string   `json:"severity"`
		CVE      string   `json:"cve"`
		CWE      int      `json:"cwe"`
		CVSSv3   float64  `json:"cvssv3"`
		Endpoint string   `json:"endpoint"`
		Tags     []string `json:"tags"`
	}
	if err := json.Unmarshal(data, &findings); err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(findings))
	}
	first := findings[0]
	if first.Title != "Remote code execution" || first.Severity != "Critical" {
		t.Fatalf("first finding = %+v", first)
	}
	if first.CVE != "CVE-2021-1234" || first.CWE != 79 {
		t.Fatalf("cve/cwe mapping = %s/%d", first.CVE, first.CWE)
	}
	if first.Endpoint != "https://a.example.com/admin" {
		t.Fatalf("endpoint = %q", first.Endpoint)
	}
	if findings[1].Severity != "Low" {
		t.Fatalf("low severity mapped to %q", findings[1].Severity)
	}
}

func TestDefectDojoCVSSv3(t *testing.T) {
	r := NewReport("example.com", "web")
	asset := r.GetOrCreateAsset("a.example.com")
	asset.Vulnerabilities = append(asset.Vulnerabilities, &Vulnerability{
		Source:     "techcve",
		TemplateID: "CVE-2023-44487",
		Title:      "Rapid Reset",
		Severity:   "high",
		MatchedAt:  "a.example.com",
		CVSS:       7.5,
	})
	path := filepath.Join(t.TempDir(), "findings.json")
	if err := r.WriteDefectDojo(path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var findings []struct {
		CVSSv3 float64 `json:"cvssv3"`
	}
	if err := json.Unmarshal(data, &findings); err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].CVSSv3 != 7.5 {
		t.Fatalf("cvssv3 = %+v, want 7.5", findings)
	}
}

func TestCweNumber(t *testing.T) {
	tests := map[string]int{
		"CWE-79":   79,
		"CWE-79.1": 79,
		"79":       79,
		"CWE-0":    0,
		"CWE-abc":  0,
		"":         0,
	}
	for in, want := range tests {
		if got := cweNumber(in); got != want {
			t.Fatalf("cweNumber(%q) = %d, want %d", in, got, want)
		}
	}
}
