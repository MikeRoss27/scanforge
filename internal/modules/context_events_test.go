package modules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	scanScope "github.com/MikeRoss27/scanforge/internal/scope"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

func TestAddArtifactEmitsDNSNameEventsOnlyWhenEnabled(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		root := t.TempDir()
		meta := filepath.Join(root, "00_meta")
		if err := os.MkdirAll(meta, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "subdomains.txt"), []byte("a.example.com\nevil.org\n"), 0644); err != nil {
			t.Fatal(err)
		}
		run := &storage.Run{RootDir: root, MetaDir: meta}
		sc, _ := scanScope.FromTarget("example.com", scanScope.ModeDomain, nil, nil)
		rc := NewRunContext("example.com", "recon", false, run, sc)
		if enabled {
			if err := rc.EnableEvents(); err != nil {
				t.Fatal(err)
			}
		}
		if err := rc.AddArtifact("subdomains", Artifact{Name: "subdomains", Type: "text", Path: "subdomains.txt"}); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filepath.Join(meta, "events.jsonl"))
		got := err == nil && strings.Contains(string(data), "a.example.com")
		if got != enabled {
			t.Fatalf("enabled=%v events.jsonl=%q err=%v", enabled, data, err)
		}
		if strings.Contains(string(data), "evil.org") {
			t.Fatal("out-of-scope value leaked into events.jsonl")
		}
	}
}
