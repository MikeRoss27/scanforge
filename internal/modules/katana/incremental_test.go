package katana

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/modules"
)

type noneFocus struct{}

func (noneFocus) Keep(string) bool { return false }
func (noneFocus) Digest() string   { return "none" }

func TestRunSkipsWhenIncrementalFocusIsEmpty(t *testing.T) {
	run := testRun(t, t.TempDir())
	if err := os.MkdirAll(filepath.Join(run.RootDir, "05_content"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(run.Path("02_http", "httpx.txt"), []byte("http://example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runCtx := modules.NewRunContext("example.com", "web", false, run)
	if err := runCtx.AddArtifact("alive_urls", modules.Artifact{Name: "alive_urls", Type: "text", Path: "02_http/httpx.txt"}); err != nil {
		t.Fatal(err)
	}
	runCtx.SetInputFocus(noneFocus{})
	executor := &recordingExecutor{}

	result, err := New("katana-test").Run(context.Background(), runCtx, executor)
	if err != nil {
		t.Fatal(err)
	}
	if len(executor.commands) != 0 {
		t.Fatalf("katana ran with an empty focus: %v", executor.commands)
	}
	if result.Status != "skipped" || !strings.Contains(result.Reason, "incremental") {
		t.Fatalf("result = %+v", result)
	}
	if _, ok := runCtx.GetArtifact("crawled_urls"); !ok {
		t.Fatal("empty crawled_urls must still be published for downstream modules")
	}
}
