package httpx

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteAliveURLs(t *testing.T) {
	dir := t.TempDir()

	input := filepath.Join(dir, "httpx.jsonl")
	output := filepath.Join(dir, "alive.txt")

	content := `{"url":"https://example.com","status_code":200}
{"url":"https://www.example.com","status_code":200}
{"url":"https://example.com","status_code":200}
{"status_code":404}
invalid json
`

	if err := os.WriteFile(input, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	count, err := WriteAliveURLs(input, output)
	if err != nil {
		t.Fatal(err)
	}

	if count != 2 {
		t.Fatalf("expected 2 alive URLs, got %d", count)
	}

	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}

	expected := "https://example.com\nhttps://www.example.com\n"

	if string(got) != expected {
		t.Fatalf("unexpected output:\n%s", string(got))
	}
}
