package report

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/storage"
)

// TestDiffSeesRecursiveAssets: `scanforge diff` compares GenerateReport
// output, so assets found only by --recursive must show up as added.
func TestDiffSeesRecursiveAssets(t *testing.T) {
	// "before": same run without the 07_recursive follow-ups.
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "01_subdomains"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "01_subdomains", "resolved.txt"), []byte("app.example.com\nwp.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	before, err := GenerateReport(dir, &storage.RunManifest{
		Target: "example.com", Profile: "web",
		Outputs: map[string]string{"resolved_hosts": "01_subdomains/resolved.txt"},
	})
	if err != nil {
		t.Fatal(err)
	}
	after := evidenceReport(t)

	delta := CompareReports(before, after)
	if len(delta.AddedAssets) != 1 || delta.AddedAssets[0] != "dev.example.com" {
		t.Errorf("added assets = %v, want [dev.example.com]", delta.AddedAssets)
	}
	if len(delta.RemovedAssets) != 0 {
		t.Errorf("removed assets = %v", delta.RemovedAssets)
	}
}

func TestFoldRecursiveTableDriven(t *testing.T) {
	tests := []struct {
		name      string
		files     map[string]string
		scope     string
		wantHosts []string
		wantNot   []string
	}{
		{
			name: "filtered list authorises raw dnsx records",
			files: map[string]string{
				"001-a-dnsx.jsonl":   `{"host":"a.example.com","a":["192.0.2.1"]}` + "\n" + `{"host":"b.example.com","a":["192.0.2.2"]}` + "\n",
				"001-a-resolved.txt": "a.example.com\n",
			},
			scope:     "*.example.com\n",
			wantHosts: []string{"a.example.com"},
			wantNot:   []string{"b.example.com"},
		},
		{
			name: "static scope re-check drops hosts the filter let through",
			files: map[string]string{
				"001-a-resolved.txt": "a.example.com\nrogue.other.com\n",
			},
			scope:     "*.example.com\n",
			wantHosts: []string{"a.example.com"},
			wantNot:   []string{"rogue.other.com"},
		},
		{
			name: "no effective scope file relies on the filtered lists only",
			files: map[string]string{
				"001-a-resolved.txt": "a.example.com\n",
				"001-a-dnsx.jsonl":   `{"host":"zzz.example.com","a":["192.0.2.9"]}` + "\n",
			},
			wantHosts: []string{"a.example.com"},
			wantNot:   []string{"zzz.example.com"},
		},
		{
			name: "alive url without prior resolved line still scoped",
			files: map[string]string{
				"001-a-alive.txt":   "https://a.example.com\n",
				"001-a-httpx.jsonl": `{"url":"https://a.example.com","host":"a.example.com","status_code":200}` + "\n",
			},
			scope:     "*.example.com\n",
			wantHosts: []string{"a.example.com"},
		},
		{
			name: "garbage jsonl is skipped, not fatal",
			files: map[string]string{
				"001-a-resolved.txt": "a.example.com\n",
				"001-a-dnsx.jsonl":   "not json\n",
			},
			scope:     "*.example.com\n",
			wantHosts: []string{"a.example.com"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			rec := filepath.Join(dir, recursiveDir)
			if err := os.MkdirAll(rec, 0o755); err != nil {
				t.Fatal(err)
			}
			for name, body := range tt.files {
				if err := os.WriteFile(filepath.Join(rec, name), []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if tt.scope != "" {
				if err := os.MkdirAll(filepath.Join(dir, "00_meta"), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "00_meta", "effective-scope.txt"), []byte(tt.scope), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			rep := NewReport("example.com", "web")
			if err := foldRecursive(dir, rep); err != nil {
				t.Fatalf("foldRecursive: %v", err)
			}
			for _, h := range tt.wantHosts {
				a, ok := rep.Assets[h]
				if !ok {
					t.Errorf("asset %q missing", h)
				} else if a.DiscoveredBy != DiscoveredByRecursive {
					t.Errorf("asset %q DiscoveredBy = %q", h, a.DiscoveredBy)
				}
			}
			for _, h := range tt.wantNot {
				if _, ok := rep.Assets[h]; ok {
					t.Errorf("asset %q must not be folded", h)
				}
			}
		})
	}
}
