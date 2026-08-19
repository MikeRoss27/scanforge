package app

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/version"
)

// fakeTool writes an executable shell script into dir and returns its path.
func fakeTool(t *testing.T, dir, name, script string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestUpdateRequiresGo(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if err := (&App{}).Update(context.Background(), UpdateOptions{}); err == nil {
		t.Fatal("expected an error when go is not in PATH")
	}
}

func TestLatestVersion(t *testing.T) {
	dir := t.TempDir()
	record := filepath.Join(dir, "args")
	fakeTool(t, dir, "go", `echo "$@" >> "`+record+`"
case "$1" in
  list) echo '{"Path":"github.com/MikeRoss27/scanforge","Version":"v0.5.0"}';;
esac`)
	t.Setenv("PATH", dir)

	info, err := latestVersion(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info.Version != "v0.5.0" {
		t.Fatalf("Version = %q, want v0.5.0", info.Version)
	}
	data, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "list -m -json github.com/MikeRoss27/scanforge@latest") {
		t.Fatalf("go invocation = %q", data)
	}
}

func TestLatestVersionError(t *testing.T) {
	dir := t.TempDir()
	fakeTool(t, dir, "go", `echo boom >&2; exit 1`)
	t.Setenv("PATH", dir)

	if _, err := latestVersion(context.Background()); err == nil {
		t.Fatal("expected an error when go list fails")
	}
}

func TestInstallDest(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "bin", "scanforge")
	if err := os.MkdirAll(filepath.Dir(exe), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exe, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}

	dest, err := installDest(context.Background(), exe)
	if err != nil {
		t.Fatal(err)
	}
	if dest != filepath.Join(dir, "bin", "scanforge") {
		t.Fatalf("dest = %q", dest)
	}
}

func TestInstallDestFallsBackToGOBIN(t *testing.T) {
	dir := t.TempDir()
	// The executable's directory does not exist, so it is not writable.
	exe := filepath.Join(dir, "missing", "scanforge")

	gobin := filepath.Join(dir, "gobin")
	if err := os.MkdirAll(gobin, 0o755); err != nil {
		t.Fatal(err)
	}
	fakeTool(t, dir, "go", `echo "`+gobin+`"`)
	t.Setenv("PATH", dir)

	dest, err := installDest(context.Background(), exe)
	if err != nil {
		t.Fatal(err)
	}
	if dest != filepath.Join(gobin, "scanforge") {
		t.Fatalf("dest = %q", dest)
	}
}

func TestBuildBinaryInstallsWithMetadata(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "scanforge")
	gobin := filepath.Join(dir, "gobin")
	if err := os.MkdirAll(gobin, 0o755); err != nil {
		t.Fatal(err)
	}
	record := filepath.Join(dir, "args")
	fakeTool(t, dir, "go", `echo "$@" >> "`+record+`"
case "$1" in
  env) echo "`+gobin+`";;
  install) : > "`+gobin+`/scanforge";;
esac`)
	fakeTool(t, dir, "git", `echo "990b8635e24c0c1e8de5af1e72d233bb43bff5e7	refs/tags/v0.5.0^{}"`)
	t.Setenv("PATH", dir)

	info := moduleInfo{Path: updateModulePath, Version: "v0.5.0"}
	if err := buildBinary(context.Background(), info, dest); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dest); err != nil {
		t.Fatalf("dest not created: %v", err)
	}
	data, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	args := string(data)
	if !strings.Contains(args, "install -ldflags") {
		t.Fatalf("go install not invoked: %q", args)
	}
	for _, want := range []string{
		"version.Version=0.5.0",
		"version.Commit=990b863",
		"version.Date=",
		"cmd/scanforge@v0.5.0",
	} {
		if !strings.Contains(args, want) {
			t.Fatalf("go args %q missing %q", args, want)
		}
	}
}

func TestBuildBinaryToleratesMissingGit(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "scanforge")
	gobin := filepath.Join(dir, "gobin")
	if err := os.MkdirAll(gobin, 0o755); err != nil {
		t.Fatal(err)
	}
	record := filepath.Join(dir, "args")
	fakeTool(t, dir, "go", `echo "$@" >> "`+record+`"
case "$1" in
  env) echo "`+gobin+`";;
  install) : > "`+gobin+`/scanforge";;
esac`)
	t.Setenv("PATH", dir) // no git available

	info := moduleInfo{Path: updateModulePath, Version: "v0.5.0"}
	if err := buildBinary(context.Background(), info, dest); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dest); err != nil {
		t.Fatalf("dest not created: %v", err)
	}
	data, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "version.Commit=unknown") {
		t.Fatalf("expected fallback commit: %q", data)
	}
}

func TestResolveCommitPrefersPeeledTag(t *testing.T) {
	dir := t.TempDir()
	fakeTool(t, dir, "git", `echo "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa	refs/tags/v0.5.0"
echo "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb	refs/tags/v0.5.0^{}"`)
	t.Setenv("PATH", dir)

	commit, err := resolveCommit(context.Background(), "v0.5.0")
	if err != nil {
		t.Fatal(err)
	}
	if commit != "bbbbbbb" {
		t.Fatalf("commit = %q, want bbbbbbb", commit)
	}
}

func TestResolveCommitNotFound(t *testing.T) {
	dir := t.TempDir()
	fakeTool(t, dir, "git", `exit 0`)
	t.Setenv("PATH", dir)

	if _, err := resolveCommit(context.Background(), "v9.9.9"); err == nil {
		t.Fatal("expected an error for an unknown tag")
	}
}

func TestUpdateAlreadyUpToDate(t *testing.T) {
	oldVersion, oldCommit := version.Version, version.Commit
	version.Version = "0.5.0"
	version.Commit = "990b863"
	defer func() {
		version.Version, version.Commit = oldVersion, oldCommit
	}()

	dir := t.TempDir()
	record := filepath.Join(dir, "args")
	fakeTool(t, dir, "go", `echo "$@" >> "`+record+`"
case "$1" in
  list) echo '{"Path":"github.com/MikeRoss27/scanforge","Version":"v0.5.0"}';;
esac`)
	t.Setenv("PATH", dir)

	if err := (&App{}).Update(context.Background(), UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "install") {
		t.Fatalf("install must be skipped when already up to date: %q", data)
	}
}
