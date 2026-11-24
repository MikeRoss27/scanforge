package modules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	scanScope "github.com/MikeRoss27/scanforge/internal/scope"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

type setFocus map[string]bool

func (f setFocus) Keep(v string) bool { return f[v] }
func (f setFocus) Digest() string     { return "d" }

func focusRunCtx(t *testing.T, input string, sc *scanScope.Scope) *RunContext {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "02_http"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "02_http", "alive.txt"), []byte(input), 0o644); err != nil {
		t.Fatal(err)
	}
	run := &storage.Run{RootDir: root, MetaDir: filepath.Join(root, "00_meta")}
	ctx := NewRunContext("example.com", "web", false, run, sc)
	ctx.Artifacts["alive_urls"] = Artifact{Name: "alive_urls", Type: "text", Path: "02_http/alive.txt"}
	return ctx
}

func TestFocusedInput(t *testing.T) {
	sc, err := scanScope.FromTarget("example.com", scanScope.ModeDomain, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	const input = "https://a.example.com\nhttps://b.example.com\nhttps://evil.org\n"
	tests := []struct {
		name      string
		focus     InputFocus
		wantLines []string
		wantStats FocusStats
		wantPath  string
	}{
		{"no focus is a no-op", nil, nil, FocusStats{}, "02_http/alive.txt"},
		{"keeps only focused", setFocus{"https://a.example.com": true}, []string{"https://a.example.com"},
			FocusStats{Active: true, Kept: 1, Total: 3}, "02_http/alive.incremental.txt"},
		{"scope is re-applied even when the focus keeps everything",
			setFocus{"https://a.example.com": true, "https://b.example.com": true, "https://evil.org": true},
			[]string{"https://a.example.com", "https://b.example.com"},
			FocusStats{Active: true, Kept: 2, Total: 3}, "02_http/alive.incremental.txt"},
		{"nothing to scan", setFocus{}, nil, FocusStats{Active: true, Kept: 0, Total: 3}, "02_http/alive.incremental.txt"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := focusRunCtx(t, input, sc)
			if tt.focus != nil {
				ctx.SetInputFocus(tt.focus)
			}
			art, stats, err := ctx.FocusedInput("alive_urls")
			if err != nil {
				t.Fatal(err)
			}
			if stats != tt.wantStats || art.Path != tt.wantPath {
				t.Fatalf("stats = %+v path = %q, want %+v %q", stats, art.Path, tt.wantStats, tt.wantPath)
			}
			if tt.focus == nil {
				return
			}
			data, err := os.ReadFile(ctx.Run.Path(art.Path))
			if err != nil {
				t.Fatal(err)
			}
			got := strings.Fields(string(data))
			if strings.Join(got, ",") != strings.Join(tt.wantLines, ",") {
				t.Fatalf("lines = %v, want %v", got, tt.wantLines)
			}
			if stats.Empty() != (tt.wantStats.Kept == 0) {
				t.Fatalf("Empty() = %v", stats.Empty())
			}
		})
	}
}

func TestFocusedInputIgnoresNonFocusableAndDryRun(t *testing.T) {
	ctx := focusRunCtx(t, "https://a.example.com\n", nil)
	ctx.SetInputFocus(setFocus{})
	ctx.Artifacts["resolved_hosts"] = Artifact{Name: "resolved_hosts", Type: "text", Path: "02_http/alive.txt"}
	if _, stats, err := ctx.FocusedInput("resolved_hosts"); err != nil || stats.Active {
		t.Fatalf("non-focusable artifact narrowed: %+v %v", stats, err)
	}
	ctx.DryRun = true
	if _, stats, err := ctx.FocusedInput("alive_urls"); err != nil || stats.Active {
		t.Fatalf("dry run narrowed: %+v %v", stats, err)
	}
}
