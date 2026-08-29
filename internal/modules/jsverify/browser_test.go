package jsverify

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
)

func TestConfiguredBrowserNameResolvesFromPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test helper uses a Unix executable")
	}
	binDir := t.TempDir()
	browser := filepath.Join(binDir, "test-chromium")
	if err := os.WriteFile(browser, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	run := testRun(t)
	runCtx := modules.NewRunContext("example.com", "web", true, run)
	if err := runCtx.AddArtifact("js_secrets", modules.Artifact{Name: "js_secrets", Type: "jsonl", Path: "06_vulns/js-secrets.jsonl"}); err != nil {
		t.Fatal(err)
	}
	if err := runCtx.AddArtifact("crawled_urls", modules.Artifact{Name: "crawled_urls", Type: "text", Path: "03_urls/crawled.txt"}); err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{"06_vulns/js-secrets.jsonl", "03_urls/crawled.txt"} {
		path := run.Path(strings.Split(rel, "/")...)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, nil, 0644); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := New("test-chromium").Run(context.Background(), runCtx, runner.NewDryRunExecutor(false)); err != nil {
		t.Fatalf("configured browser on PATH should resolve: %v", err)
	}
}
