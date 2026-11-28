package modules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeStderrFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "stderr.log")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write stderr file: %v", err)
	}
	return path
}

func TestFailureReason(t *testing.T) {
	tests := []struct {
		name string
		path func(t *testing.T) string
		want string
	}{
		{
			name: "missing file",
			path: func(t *testing.T) string { return filepath.Join(t.TempDir(), "absent.log") },
			want: "",
		},
		{
			name: "empty path",
			path: func(t *testing.T) string { return "" },
			want: "",
		},
		{
			name: "empty file",
			path: func(t *testing.T) string { return writeStderrFile(t, "") },
			want: "",
		},
		{
			name: "single line",
			path: func(t *testing.T) string {
				return writeStderrFile(t, "[FTL] Could not create runner: write /tmp/x/CURRENT.0: disk quota exceeded\n")
			},
			want: "[FTL] Could not create runner: write /tmp/x/CURRENT.0: disk quota exceeded",
		},
		{
			name: "keeps only the last lines",
			path: func(t *testing.T) string {
				return writeStderrFile(t, "line1\nline2\nline3\nline4\nline5\n")
			},
			want: "line3 | line4 | line5",
		},
		{
			name: "skips blank lines",
			path: func(t *testing.T) string {
				return writeStderrFile(t, "line1\n\n\nline2\n")
			},
			want: "line1 | line2",
		},
		{
			name: "strips ANSI color codes",
			path: func(t *testing.T) string {
				return writeStderrFile(t, "\x1b[31mFTL\x1b[0m something failed\n")
			},
			want: "FTL something failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FailureReason(tt.path(t))
			if got != tt.want {
				t.Errorf("FailureReason() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFailureStatus(t *testing.T) {
	t.Run("without stderr content falls back to exit code only", func(t *testing.T) {
		got := FailureStatus(1, "")
		want := "failed (exit code 1)"
		if got != want {
			t.Errorf("FailureStatus() = %q, want %q", got, want)
		}
	})

	t.Run("appends the stderr excerpt when available", func(t *testing.T) {
		path := writeStderrFile(t, "disk quota exceeded\n")
		got := FailureStatus(1, path)
		if !strings.HasPrefix(got, "failed (exit code 1): ") {
			t.Fatalf("FailureStatus() = %q, want prefix %q", got, "failed (exit code 1): ")
		}
		if !strings.Contains(got, "disk quota exceeded") {
			t.Errorf("FailureStatus() = %q, want it to contain the stderr excerpt", got)
		}
	})
}
