package dnsx

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

func TestWriteResolvedHostsDeduplicatesJSONL(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "dnsx.jsonl")
	output := filepath.Join(dir, "dnsx.txt")
	data := "{\"host\":\"api.example.com\"}\ninvalid\n{\"host\":\"api.example.com\"}\n{\"host\":\"www.example.com\"}\n"
	if err := os.WriteFile(input, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}
	if err := writeResolvedHosts(input, output); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if want := "api.example.com\nwww.example.com\n"; string(got) != want {
		t.Fatalf("resolved hosts = %q, want %q", got, want)
	}
}

func TestMergeBruteInputCombinesAndDeduplicates(t *testing.T) {
	run := &storage.Run{RootDir: t.TempDir(), CommandsLog: filepath.Join(t.TempDir(), "commands.log")}
	if err := os.MkdirAll(filepath.Join(run.RootDir, "01_subdomains"), 0755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(run.RootDir, "01_subdomains", "subdomains.txt"), "example.com\napi.example.com\n")
	writeFile(t, filepath.Join(run.RootDir, "01_subdomains", "brute.txt"), "api.example.com\nvpn.example.com\n")

	runCtx := modules.NewRunContext("example.com", "web", false, run)
	if err := runCtx.AddArtifact("subdomains", modules.Artifact{Name: "subdomains", Type: "text", Path: "01_subdomains/subdomains.txt"}); err != nil {
		t.Fatal(err)
	}
	if err := runCtx.AddArtifact("brute_subdomains", modules.Artifact{Name: "brute_subdomains", Type: "text", Path: "01_subdomains/brute.txt"}); err != nil {
		t.Fatal(err)
	}

	input := mergeBruteInput(runCtx, modules.Artifact{Name: "subdomains", Type: "text", Path: "01_subdomains/subdomains.txt"})
	got, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	if want := "example.com\napi.example.com\nvpn.example.com\n"; string(got) != want {
		t.Fatalf("merged input = %q, want %q", got, want)
	}
}

func TestMergeBruteInputReturnsSubdomainsWithoutBruteArtifact(t *testing.T) {
	run := &storage.Run{RootDir: t.TempDir(), CommandsLog: filepath.Join(t.TempDir(), "commands.log")}
	runCtx := modules.NewRunContext("example.com", "web", false, run)
	if err := runCtx.AddArtifact("subdomains", modules.Artifact{Name: "subdomains", Type: "text", Path: "01_subdomains/subdomains.txt"}); err != nil {
		t.Fatal(err)
	}
	input := mergeBruteInput(runCtx, modules.Artifact{Name: "subdomains", Type: "text", Path: "01_subdomains/subdomains.txt"})
	if want := filepath.Join(run.RootDir, "01_subdomains", "subdomains.txt"); input != want {
		t.Fatalf("input = %q, want %q", input, want)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}
