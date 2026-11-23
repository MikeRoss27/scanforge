package cli

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/vulnintel"
)

func TestIntelStatusAndUpdate(t *testing.T) {
	t.Setenv(vulnintel.EnvDir, filepath.Join(t.TempDir(), "intel"))

	kev, err := os.ReadFile(filepath.Join("..", "vulnintel", "testdata", "kev.json"))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(kev)
	}))
	defer srv.Close()

	orig := newIntelClient
	newIntelClient = func() *vulnintel.Client {
		return &vulnintel.Client{HTTP: srv.Client(), KEVURL: srv.URL}
	}
	defer func() { newIntelClient = orig }()

	run := func(args ...string) string {
		var buf bytes.Buffer
		cmd := NewIntelCommand()
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)
		cmd.SetArgs(args)
		if err := cmd.Execute(); err != nil {
			t.Fatalf("intel %v: %v", args, err)
		}
		return buf.String()
	}

	if out := run("status"); !strings.Contains(out, "Cache empty") || !strings.Contains(out, "nvd   not downloaded") {
		t.Fatalf("unexpected empty status:\n%s", out)
	}
	if out := run("update", "--source", "kev"); !strings.Contains(out, "kev: 2 records") {
		t.Fatalf("unexpected update output:\n%s", out)
	}
	if out := run("status"); !strings.Contains(out, "kev") || strings.Contains(out, "Cache empty") {
		t.Fatalf("unexpected status after update:\n%s", out)
	}

	cmd := NewIntelCommand()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"update", "--source", "bogus"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("unknown source must fail")
	}
}
