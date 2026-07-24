package dnsx

import (
	"os"
	"path/filepath"
	"testing"
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
