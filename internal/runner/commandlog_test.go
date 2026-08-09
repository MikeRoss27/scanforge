package runner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestShellQuote(t *testing.T) {
	tests := []struct {
		name string
		arg  string
		want string
	}{
		{"bare flag", "-silent", "-silent"},
		{"path", "/usr/share/wordlists/dirb/common.txt", "/usr/share/wordlists/dirb/common.txt"},
		{"header with space", "Authorization: Bearer tok", "'Authorization: Bearer tok'"},
		{"header with angle brackets", "X-A: <token>", "'X-A: <token>'"},
		{"embedded single quote", "it's", `'it'\''s'`},
		{"newline escaped", "X: a\nb", `'X: a\nb'`},
		{"tab escaped", "a\tb", `'a\tb'`},
		{"empty", "", "''"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shellQuote(tt.arg); got != tt.want {
				t.Fatalf("shellQuote(%q) = %q, want %q", tt.arg, got, tt.want)
			}
		})
	}
}

func TestAppendCommandLogQuotesHeaders(t *testing.T) {
	path := filepath.Join(t.TempDir(), "commands.log")
	cmd := Command{
		Name: "httpx",
		Args: []string{"-H", "Authorization: Bearer tok", "-H", "X-Evil: a\nb"},
	}
	if err := AppendCommandLog(path, cmd); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	log := string(data)
	if strings.Contains(log, "a\nb\n") {
		t.Fatalf("log contains an injected line:\n%q", log)
	}
	if !strings.Contains(log, "'Authorization: Bearer tok'") {
		t.Fatalf("header not quoted in log:\n%s", log)
	}
}
