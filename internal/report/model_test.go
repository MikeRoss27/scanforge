package report

import (
	"encoding/json"
	"testing"
	"time"
)

func TestNewReport(t *testing.T) {
	rep := NewReport("example.com", "web")
	if rep.Target != "example.com" {
		t.Errorf("expected target %q, got %q", "example.com", rep.Target)
	}
	if rep.Profile != "web" {
		t.Errorf("expected profile %q, got %q", "web", rep.Profile)
	}
	if rep.Status != "" {
		t.Errorf("expected empty status, got %q", rep.Status)
	}
	if rep.Assets == nil {
		t.Fatal("expected non-nil assets map")
	}
	if len(rep.Assets) != 0 {
		t.Errorf("expected empty assets map, got %d entries", len(rep.Assets))
	}
}

func TestGetOrCreateAssetCreates(t *testing.T) {
	rep := NewReport("example.com", "web")
	asset := rep.GetOrCreateAsset("api.example.com")

	if asset == nil {
		t.Fatal("expected non-nil asset")
	}
	if asset.Name != "api.example.com" {
		t.Errorf("expected name %q, got %q", "api.example.com", asset.Name)
	}
	if asset.Ports == nil {
		t.Error("expected non-nil ports map on new asset")
	}
	if len(rep.Assets) != 1 {
		t.Errorf("expected 1 asset in report, got %d", len(rep.Assets))
	}
	if rep.Assets["api.example.com"] != asset {
		t.Error("expected asset to be stored under its name key")
	}
}

func TestGetOrCreateAssetReturnsExisting(t *testing.T) {
	rep := NewReport("example.com", "web")
	first := rep.GetOrCreateAsset("api.example.com")
	first.IPs = append(first.IPs, "10.0.0.1")

	second := rep.GetOrCreateAsset("api.example.com")
	if second != first {
		t.Fatal("expected same asset instance on second call")
	}
	if len(second.IPs) != 1 {
		t.Errorf("expected existing asset to keep its state, got %v", second.IPs)
	}
	if len(rep.Assets) != 1 {
		t.Errorf("expected no duplicate assets, got %d", len(rep.Assets))
	}
}

func TestGetOrCreateAssetDistinctNames(t *testing.T) {
	rep := NewReport("example.com", "web")
	a := rep.GetOrCreateAsset("a.example.com")
	b := rep.GetOrCreateAsset("b.example.com")
	if a == b {
		t.Fatal("expected distinct assets for distinct names")
	}
	if len(rep.Assets) != 2 {
		t.Errorf("expected 2 assets, got %d", len(rep.Assets))
	}
}

func TestReportJSONMarshal(t *testing.T) {
	rep := NewReport("example.com", "web")
	rep.Status = "completed"
	rep.StartedAt = time.Unix(1700000000, 0).UTC()
	rep.CompletedAt = time.Unix(1700000100, 0).UTC()
	asset := rep.GetOrCreateAsset("example.com")
	asset.Ports[443] = &Port{Number: 443, Protocol: "tcp", Service: "https"}
	asset.Vulnerabilities = append(asset.Vulnerabilities, &Vulnerability{
		Source:     "nuclei",
		TemplateID: "cve-2020-1",
		Title:      "Example finding",
		Severity:   "high",
	})

	data, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("unexpected marshal error: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}

	if decoded["target"] != "example.com" {
		t.Errorf("expected target in JSON, got %v", decoded["target"])
	}
	if decoded["status"] != "completed" {
		t.Errorf("expected status in JSON, got %v", decoded["status"])
	}
	if decoded["profile"] != "web" {
		t.Errorf("expected profile in JSON, got %v", decoded["profile"])
	}
	assets, ok := decoded["assets"].(map[string]any)
	if !ok {
		t.Fatalf("expected assets object in JSON, got %T", decoded["assets"])
	}
	host, ok := assets["example.com"].(map[string]any)
	if !ok {
		t.Fatalf("expected asset entry in JSON, got %T", assets["example.com"])
	}
	if host["name"] != "example.com" {
		t.Errorf("expected asset name in JSON, got %v", host["name"])
	}
}

func TestVulnerabilityJSONOmitEmpty(t *testing.T) {
	v := &Vulnerability{
		Source:     "nuclei",
		TemplateID: "tpl-1",
		Title:      "Title",
		Severity:   "medium",
		MatchedAt:  "example.com",
	}

	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("unexpected marshal error: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}

	if _, ok := decoded["evidence"]; ok {
		t.Error("expected evidence to be omitted when empty")
	}
	if _, ok := decoded["tags"]; ok {
		t.Error("expected tags to be omitted when empty")
	}
	if _, ok := decoded["references"]; ok {
		t.Error("expected references to be omitted when empty")
	}
	if decoded["source"] != "nuclei" {
		t.Errorf("expected source in JSON, got %v", decoded["source"])
	}
}
