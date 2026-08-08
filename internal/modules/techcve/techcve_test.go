package techcve

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

func TestRequiresAndProduces(t *testing.T) {
	if got, want := New().Requires(), []string{"httpx_raw"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Requires() = %v, want %v", got, want)
	}
	if got, want := New().Produces(), []string{"cve_findings"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Produces() = %v, want %v", got, want)
	}
}

func TestSplitTechVersion(t *testing.T) {
	cases := map[string][2]string{
		"WordPress:6.3.1":      {"WordPress", "6.3.1"},
		"jQuery UI:1.13.1":     {"jQuery UI", "1.13.1"},
		"Apache Tomcat 9.0.79": {"Apache Tomcat", "9.0.79"},
		"nginx 1.22.1":         {"nginx", "1.22.1"},
		"Bootstrap":            {"Bootstrap", ""},
	}
	for input, want := range cases {
		name, version := splitTechVersion(input)
		if name != want[0] || version != want[1] {
			t.Errorf("splitTechVersion(%q) = (%q, %q), want (%q, %q)", input, name, version, want[0], want[1])
		}
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"3.5.0", "3.5.0", 0},
		{"3.4.99", "3.5.0", -1},
		{"10.1.18", "9.0.81", 1},
		{"1.25.3", "1.25.3", 0},
		{"6.4", "6.4.0", 0},
		{"8.2.19", "8.2.8", 1},
		{"v1.2.3", "1.2.4", -1},
	}
	for _, tc := range cases {
		if got := compareVersions(tc.a, tc.b); got != tc.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestVersionAffected(t *testing.T) {
	cases := []struct {
		version, min, max string
		want              bool
	}{
		{"3.4.1", "", "3.5.0", true},
		{"3.5.0", "", "3.5.0", false},
		{"9.0.79", "9.0.0", "9.0.81", true},
		{"10.1.18", "10.0.0", "10.1.18", false},
		{"8.2.10", "8.2.0", "8.2.19", true},
		{"8.1.12", "8.2.0", "8.2.19", false},
		{"", "", "3.5.0", false},
	}
	for _, tc := range cases {
		if got := versionAffected(tc.version, tc.min, tc.max); got != tc.want {
			t.Errorf("versionAffected(%q, %q, %q) = %v, want %v", tc.version, tc.min, tc.max, got, tc.want)
		}
	}
}

func TestRunFlagsVulnerableVersions(t *testing.T) {
	run := testRun(t)
	writeFile(t, run.Path("02_http", "httpx.jsonl"),
		`{"host":"example.com","tech":["jQuery UI:1.13.1","Bootstrap","nginx:1.22.1"]}`+"\n")
	writeFile(t, run.Path("03_fingerprint", "whatweb.txt"),
		"http://example.com WordPress[6.3] ApacheTomcat[9.0.79] jQuery[3.4.1]\n")

	runCtx := modules.NewRunContext("example.com", "deep", false, run)
	if err := runCtx.AddArtifact("httpx_raw", modules.Artifact{Name: "httpx_raw", Type: "jsonl", Path: "02_http/httpx.jsonl"}); err != nil {
		t.Fatal(err)
	}
	if err := runCtx.AddArtifact("whatweb_raw", modules.Artifact{Name: "whatweb_raw", Type: "text", Path: "03_fingerprint/whatweb.txt"}); err != nil {
		t.Fatal(err)
	}

	result, err := New().Run(context.Background(), runCtx, nil)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Status != "completed" {
		t.Fatalf("Run() status = %q, want completed", result.Status)
	}
	if _, ok := runCtx.GetArtifact("cve_findings"); !ok {
		t.Fatal("cve_findings artifact was not published")
	}

	findings := readFindings(t, run.Path(outputRel))
	byCVE := make(map[string]finding)
	for _, f := range findings {
		byCVE[f.CVEID] = f
	}
	if _, ok := byCVE["CVE-2022-31160"]; !ok {
		t.Fatalf("missing jQuery UI finding, got %+v", findings)
	}
	if _, ok := byCVE["CVE-2023-44487"]; !ok {
		t.Fatalf("missing nginx finding, got %+v", findings)
	}
	tomcat, ok := byCVE["CVE-2023-42795"]
	if !ok || tomcat.Tech != "ApacheTomcat" || tomcat.Version != "9.0.79" {
		t.Fatalf("bad tomcat finding: %+v", tomcat)
	}
	if _, ok := byCVE["CVE-2020-11022"]; !ok {
		t.Fatalf("missing jquery finding from whatweb, got %+v", findings)
	}
	// Bootstrap has no version and must not match anything.
	for _, f := range findings {
		if f.Tech == "Bootstrap" {
			t.Fatalf("unexpected finding for version-less tech: %+v", f)
		}
	}
}

func TestRunIgnoresPatchedVersions(t *testing.T) {
	run := testRun(t)
	writeFile(t, run.Path("02_http", "httpx.jsonl"),
		`{"host":"example.com","tech":["jQuery:3.5.0","nginx:1.25.3"]}`+"\n")

	runCtx := modules.NewRunContext("example.com", "deep", false, run)
	if err := runCtx.AddArtifact("httpx_raw", modules.Artifact{Name: "httpx_raw", Type: "jsonl", Path: "02_http/httpx.jsonl"}); err != nil {
		t.Fatal(err)
	}

	if _, err := New().Run(context.Background(), runCtx, nil); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	findings := readFindings(t, run.Path(outputRel))
	if len(findings) != 0 {
		t.Fatalf("expected no findings for patched versions, got %+v", findings)
	}
}

func testRun(t *testing.T) *storage.Run {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{"00_meta", "02_http", "03_fingerprint", "06_vulns"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0755); err != nil {
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
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func readFindings(t *testing.T, path string) []finding {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		return nil
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
