package screenshot

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

func TestRequiresAndProduces(t *testing.T) {
	m := New("")
	if got, want := m.Requires(), []string{"alive_urls"}; !equal(got, want) {
		t.Fatalf("Requires() = %v, want %v", got, want)
	}
	if got, want := m.Produces(), []string{"screenshots"}; !equal(got, want) {
		t.Fatalf("Produces() = %v, want %v", got, want)
	}
}

func TestRunDryRunBuildsScreenshotCommand(t *testing.T) {
	run := testRun(t)
	writeFile(t, run.Path("02_http", "alive.txt"), "https://a.example.com\n")

	runCtx := modules.NewRunContext("example.com", "web", true, run)
	if err := runCtx.AddArtifact("alive_urls", modules.Artifact{Name: "alive_urls", Type: "text", Path: "02_http/alive.txt"}); err != nil {
		t.Fatal(err)
	}

	if _, err := New("httpx").Run(context.Background(), runCtx, runner.NewDryRunExecutor(false)); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if art, ok := runCtx.GetArtifact("screenshots"); !ok || art.Path != outputDir {
		t.Fatalf("screenshots artifact missing: %+v", art)
	}

	log, err := os.ReadFile(run.CommandsLog)
	if err != nil {
		t.Fatal(err)
	}
	line := string(log)
	for _, want := range []string{"httpx", "-screenshot", "-screenshot-dir", outputDir, "alive.txt"} {
		if !strings.Contains(line, want) {
			t.Fatalf("commands log misses %q:\n%s", want, line)
		}
	}
}

func TestScreenshotFilesListsPNGOnly(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a.example.com.png", "b.example.com.png", "notes.txt", "sub.png.log"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	files, err := ScreenshotFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 || files[0] != "a.example.com.png" || files[1] != "b.example.com.png" {
		t.Fatalf("ScreenshotFiles() = %v", files)
	}
}

func testRun(t *testing.T) *storage.Run {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{"00_meta", "02_http"} {
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

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
