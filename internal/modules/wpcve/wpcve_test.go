package wpcve

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"5.6.0", "5.7.1", -1},
		{"6.4.2", "5.8.3", 1},
		{"3.5.0", "3.5.0", 0},
		{"v1.2.3", "1.2.3", 0},
		{"10.1", "9.0.81", 1},
	}
	for _, tc := range cases {
		if got := compareVersions(tc.a, tc.b); got != tc.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestMatchCoreAdvisory(t *testing.T) {
	entries, err := loadDataset()
	if err != nil {
		t.Fatal(err)
	}
	findings := match(entries, "example.com", "wordpress", "5.7.0")
	byID := map[string]finding{}
	for _, f := range findings {
		byID[f.CVEID] = f
	}
	if _, ok := byID["CVE-2022-21661"]; !ok {
		t.Fatalf("expected CVE-2022-21661 for WP 5.7.0, got %+v", findings)
	}
	if _, ok := byID["CVE-2021-29447"]; !ok {
		t.Fatalf("expected CVE-2021-29447 for WP 5.7.0, got %+v", findings)
	}

	findings = match(entries, "example.com", "wordpress", "6.9.0")
	for _, f := range findings {
		if f.Severity == "high" || f.Severity == "critical" {
			t.Fatalf("unexpected %s core advisory for WP 6.9.0: %+v", f.Severity, f)
		}
	}
}

func TestMatchPluginAdvisory(t *testing.T) {
	entries, err := loadDataset()
	if err != nil {
		t.Fatal(err)
	}
	findings := match(entries, "example.com", "contact-form-7", "5.3.0")
	byCVE := map[string]finding{}
	for _, f := range findings {
		byCVE[f.CVEID] = f
	}
	f, ok := byCVE["CVE-2020-35489"]
	if !ok {
		t.Fatalf("expected CVE-2020-35489 for contact-form-7 5.3.0, got %+v", findings)
	}
	if f.Severity != "critical" {
		t.Fatalf("CVE-2020-35489 severity = %q, want critical", f.Severity)
	}
	for _, f := range match(entries, "example.com", "contact-form-7", "6.1.0") {
		if f.CVEID == "CVE-2020-35489" {
			t.Fatalf("CVE-2020-35489 must not match contact-form-7 6.1.0")
		}
	}

	findings = match(entries, "example.com", "duplicator", "1.3.0")
	byCVE = map[string]finding{}
	for _, f := range findings {
		byCVE[f.CVEID] = f
	}
	if _, ok := byCVE["CVE-2020-11738"]; !ok {
		t.Fatalf("expected CVE-2020-11738 for duplicator 1.3.0, got %+v", findings)
	}

	elementor := match(entries, "example.com", "elementor", "3.5.5")
	byCVE = map[string]finding{}
	for _, f := range elementor {
		byCVE[f.CVEID] = f
	}
	if _, ok := byCVE["CVE-2022-29455"]; !ok {
		t.Fatalf("expected CVE-2022-29455 for elementor 3.5.5, got %+v", elementor)
	}
	for _, f := range match(entries, "example.com", "elementor", "3.6.0") {
		if f.CVEID == "CVE-2022-29455" {
			t.Fatalf("CVE-2022-29455 must not match elementor 3.6.0")
		}
	}
}

func TestRunCorrelatesArtifacts(t *testing.T) {
	run := testRun(t)
	writeFile(t, run.Path("04_wordpress", "wp-fingerprint.jsonl"),
		`{"target":"https://example.com","is_wordpress":true,"core_version":"5.7.0","sources":["generator"],"confidence":"high","fetched_at":"2026-11-18T00:00:00Z"}`+"\n")
	writeFile(t, run.Path("04_wordpress", "wp-plugins.jsonl"),
		`{"url":"https://example.com","plugin":"contact-form-7","version":"5.3.0","source":"readme","detection":"aggressive","confidence":"high"}`+"\n")
	writeFile(t, run.Path("04_wordpress", "wp-themes.jsonl"),
		`{"url":"https://example.com","theme":"x","version":"1.0","source":"asset","detection":"passive","confidence":"low"}`+"\n")

	runCtx := modules.NewRunContext("example.com", "wp", true, run)
	if err := runCtx.AddArtifact("wp_fingerprint", modules.Artifact{Name: "wp_fingerprint", Type: "jsonl", Path: "04_wordpress/wp-fingerprint.jsonl"}); err != nil {
		t.Fatal(err)
	}
	if err := runCtx.AddArtifact("wp_plugins", modules.Artifact{Name: "wp_plugins", Type: "jsonl", Path: "04_wordpress/wp-plugins.jsonl"}); err != nil {
		t.Fatal(err)
	}
	if err := runCtx.AddArtifact("wp_themes", modules.Artifact{Name: "wp_themes", Type: "jsonl", Path: "04_wordpress/wp-themes.jsonl"}); err != nil {
		t.Fatal(err)
	}

	result, err := New().Run(context.Background(), runCtx, nil)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Status != "completed" {
		t.Fatalf("Run() status = %q, want completed", result.Status)
	}
	if _, ok := runCtx.GetArtifact("wp_cve_findings"); !ok {
		t.Fatal("wp_cve_findings artifact was not published")
	}

	findings := readFindings(t, run.Path(outputRel))
	seen := map[string]struct{}{}
	for _, f := range findings {
		seen[f.CVEID] = struct{}{}
	}
	for _, want := range []string{"CVE-2022-21661", "CVE-2021-29447", "CVE-2020-35489"} {
		if _, ok := seen[want]; !ok {
			t.Fatalf("missing %s in findings %+v", want, findings)
		}
	}
	for _, f := range findings {
		if f.Host != "example.com" {
			t.Fatalf("host = %q, want example.com", f.Host)
		}
	}
}

func TestRequiresAndProduces(t *testing.T) {
	if got := New().Requires(); !reflect.DeepEqual(got, []string{"wp_fingerprint"}) {
		t.Fatalf("Requires() = %v", got)
	}
	if got := New().Produces(); !reflect.DeepEqual(got, []string{"wp_cve_findings"}) {
		t.Fatalf("Produces() = %v", got)
	}
}

func testRun(t *testing.T) *storage.Run {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{"00_meta", "04_wordpress", "06_vulns"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return &storage.Run{
		RootDir:     root,
		MetaDir:     filepath.Join(root, "00_meta"),
		CommandsLog: filepath.Join(root, "00_meta", "commands.log"),
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFindings(t *testing.T, path string) []finding {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var findings []finding
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	for decoder.More() {
		var item finding
		if err := decoder.Decode(&item); err != nil {
			t.Fatalf("invalid finding JSON: %v", err)
		}
		findings = append(findings, item)
	}
	return findings
}
