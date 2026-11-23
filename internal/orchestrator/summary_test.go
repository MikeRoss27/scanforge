package orchestrator

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

func TestModuleSummary(t *testing.T) {
	run := &storage.Run{RootDir: t.TempDir()}
	if err := os.WriteFile(filepath.Join(run.RootDir, "subs.txt"), []byte("a.com\nb.com\n\nc.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	runCtx := modules.NewRunContext("example.com", "test", false, run)
	if err := runCtx.AddArtifact("subdomains", modules.Artifact{Name: "subdomains", Type: "text", Path: "subs.txt"}); err != nil {
		t.Fatal(err)
	}

	mod := &mockModule{name: "subfinder", produces: []string{"subdomains"}}
	got := moduleSummary(runCtx, mod, &modules.Result{Name: "subfinder", Status: "completed"})
	if got != "3 subdomains" {
		t.Errorf("expected %q, got %q", "3 subdomains", got)
	}
}

func TestModuleSummarySkipsEmptyOutputAndDryRun(t *testing.T) {
	run := &storage.Run{RootDir: t.TempDir()}
	if err := os.WriteFile(filepath.Join(run.RootDir, "subs.txt"), []byte("\n\n"), 0644); err != nil {
		t.Fatal(err)
	}
	runCtx := modules.NewRunContext("example.com", "test", false, run)
	if err := runCtx.AddArtifact("subdomains", modules.Artifact{Name: "subdomains", Type: "text", Path: "subs.txt"}); err != nil {
		t.Fatal(err)
	}
	mod := &mockModule{name: "subfinder", produces: []string{"subdomains"}}

	if got := moduleSummary(runCtx, mod, &modules.Result{Name: "subfinder", Status: "completed"}); got != "" {
		t.Errorf("expected empty summary for empty file, got %q", got)
	}
	if got := moduleSummary(runCtx, mod, &modules.Result{Name: "subfinder", Status: "failed"}); got != "" {
		t.Errorf("expected empty summary for failed module, got %q", got)
	}

	dry := modules.NewRunContext("example.com", "test", true, run)
	if got := moduleSummary(dry, mod, &modules.Result{Name: "subfinder", Status: "completed"}); got != "" {
		t.Errorf("expected empty summary for dry run, got %q", got)
	}
}

func TestModuleSummaryCustomSummarizers(t *testing.T) {
	wafTranscript := "   ______\n  (  W00f! )\n" +
		"[*] Checking https://a.example.com\n" +
		"[+] Generic Detection results:\n" +
		"[*] The site https://a.example.com seems to be behind a WAF or some sort of security solution\n" +
		"[~] Number of requests: 6\n" +
		"[*] Checking https://b.example.com\n" +
		"[-] No WAF detected by the generic detection\n" +
		"[*] Checking https://c.example.com\n" +
		"[+] The site https://c.example.com is behind Cloudflare (Cloudflare Inc.) WAF.\n"
	tests := []struct {
		name     string
		artifact string
		content  string
		want     string
	}{
		{"ffuf results", "discovered_paths", `{"results":[{"url":"a"},{"url":"b"},{"url":"c"}],"config":{}}`, "3 paths"},
		{"ffuf single", "discovered_paths", `{"results":[{"url":"a"}]}`, "1 path"},
		{"ffuf empty", "discovered_paths", `{"results":[]}`, ""},
		{"ffuf malformed", "discovered_paths", `not json`, ""},
		{"wafw00f mixed", "waf_raw", wafTranscript, "2/3 hosts behind a WAF"},
		{"wafw00f none", "waf_raw", "[*] Checking https://a.example.com\n[-] No WAF detected\n", "no WAF on 1 host"},
		{"wafw00f banner only", "waf_raw", "  (  W00f! )\n", ""},
		// -matcher-status makes nuclei write one line per template *attempted*,
		// not per match: a WAF catch-all page alone can produce hundreds of
		// identical-looking non-matches (reproduces a real run where 320 lines
		// were all matcher-status:false request-timeout noise, previously
		// shown to the operator as "320 findings").
		{"nuclei all non-matches", "nuclei_raw", `{"template-id":"a","matcher-status":false}` + "\n" + `{"template-id":"b","matcher-status":false}` + "\n", ""},
		{"nuclei mixed", "nuclei_raw", `{"template-id":"a","matcher-status":true}` + "\n" + `{"template-id":"b","matcher-status":false}` + "\n" + `{"template-id":"c","matcher-status":true}` + "\n", "2 findings"},
		{"nuclei legacy no status field", "nuclei_raw", `{"template-id":"a"}` + "\n", "1 finding"},
		{"nuclei malformed line", "nuclei_raw", "not json\n" + `{"template-id":"a","matcher-status":true}` + "\n", "1 finding"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			run := &storage.Run{RootDir: t.TempDir()}
			if err := os.WriteFile(filepath.Join(run.RootDir, "out"), []byte(tt.content), 0644); err != nil {
				t.Fatal(err)
			}
			runCtx := modules.NewRunContext("example.com", "test", false, run)
			if err := runCtx.AddArtifact(tt.artifact, modules.Artifact{Name: tt.artifact, Type: "json", Path: "out"}); err != nil {
				t.Fatal(err)
			}
			mod := &mockModule{name: "m", produces: []string{tt.artifact}}
			if got := moduleSummary(runCtx, mod, &modules.Result{Name: "m", Status: "completed"}); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestModuleSummaryFallsBackToRawArtifact(t *testing.T) {
	run := &storage.Run{RootDir: t.TempDir()}
	if err := os.WriteFile(filepath.Join(run.RootDir, "raw.jsonl"), []byte("{\"a\":1}\n{\"b\":2}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	runCtx := modules.NewRunContext("example.com", "test", false, run)
	if err := runCtx.AddArtifact("nuclei_raw", modules.Artifact{Name: "nuclei_raw", Type: "jsonl", Path: "raw.jsonl"}); err != nil {
		t.Fatal(err)
	}

	mod := &mockModule{name: "nuclei", produces: []string{"nuclei_raw"}}
	got := moduleSummary(runCtx, mod, &modules.Result{Name: "nuclei", Status: "completed"})
	if got != "2 findings" {
		t.Errorf("expected %q, got %q", "2 findings", got)
	}
}
