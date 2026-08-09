package app

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/config"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

type fakeScopePrompter struct {
	tty      bool
	accepted bool
	calls    int
	proposal ScopeProposal
}

func (p *fakeScopePrompter) IsTTY() bool {
	return p.tty
}

func (p *fakeScopePrompter) Confirm(proposal ScopeProposal) (bool, error) {
	p.calls++
	p.proposal = proposal
	return p.accepted, nil
}

func TestResolveScopeUsesConfiguredFileWhenItAllowsTarget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scope.txt")
	if err := os.WriteFile(path, []byte("example.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.DefaultScope = path

	resolved, err := resolveScope(cfg, "example.com", "", "", nil, nil)
	if err != nil {
		t.Fatalf("resolveScope() error = %v", err)
	}
	if resolved.proposal.Source != scopeSourceConfigured || resolved.proposal.Mode != scopeModeFile {
		t.Fatalf("proposal = %+v, want configured file", resolved.proposal)
	}
}

func TestResolveScopeFallsBackWhenConfiguredFileRejectsTarget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scope.txt")
	if err := os.WriteFile(path, []byte("other.example\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.DefaultScope = path

	resolved, err := resolveScope(cfg, "example.com", "", "", nil, nil)
	if err != nil {
		t.Fatalf("resolveScope() error = %v", err)
	}
	if resolved.proposal.Source != scopeSourceImplicit {
		t.Fatalf("source = %q, want implicit", resolved.proposal.Source)
	}
	if got, want := resolved.proposal.Entries, []string{"example.com"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("entries = %v, want %v", got, want)
	}
}

func TestResolveScopeExplicitFileNeverFallsBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scope.txt")
	if err := os.WriteFile(path, []byte("other.example\n"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := resolveScope(config.Default(), "example.com", path, "", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "explicit scope") {
		t.Fatalf("resolveScope() error = %v, want explicit scope rejection", err)
	}
}

func TestResolveScopeRejectsExplicitFileWithImplicitFlags(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scope.txt")
	if err := os.WriteFile(path, []byte("example.com\n"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := resolveScope(config.Default(), "example.com", path, "domain", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "cannot be combined") {
		t.Fatalf("resolveScope() error = %v, want conflicting flags error", err)
	}
}

func TestResolveScopeAppliesDomainAdditionsAndExclusions(t *testing.T) {
	resolved, err := resolveScope(
		config.Default(),
		"example.com",
		"",
		"domain",
		[]string{"api.other.test", "10.0.0.0/24"},
		[]string{"admin.example.com"},
	)
	if err != nil {
		t.Fatalf("resolveScope() error = %v", err)
	}
	want := []string{
		"api.other.test",
		"example.com",
		"*.example.com",
		"10.0.0.0/24",
		"!admin.example.com",
	}
	if !reflect.DeepEqual(resolved.proposal.Entries, want) {
		t.Fatalf("entries = %v, want %v", resolved.proposal.Entries, want)
	}
	if resolved.value.IsAllowed("admin.example.com") {
		t.Fatal("excluded host should not be allowed")
	}
	if !resolved.value.IsAllowed("www.example.com") {
		t.Fatal("domain mode should allow subdomains")
	}
}

func TestRunRequiresConfirmationOutsideTTYEvenForDryRun(t *testing.T) {
	dir := t.TempDir()
	application := New(filepath.Join(dir, "missing-config.yaml"))
	prompter := &fakeScopePrompter{tty: false}
	application.ScopePrompter = prompter

	err := application.Run(context.Background(), RunOptions{
		Target:  "example.com",
		Profile: "passive",
		DryRun:  true,
	})
	if err == nil || !strings.Contains(err.Error(), "--confirm-scope") {
		t.Fatalf("Run() error = %v, want non-interactive confirmation error", err)
	}
	if prompter.calls != 0 {
		t.Fatalf("prompt calls = %d, want 0 outside a TTY", prompter.calls)
	}
}

func TestRunStopsWhenInteractiveScopeIsDeclined(t *testing.T) {
	dir := t.TempDir()
	configPath := writeTestConfig(t, dir)
	application := New(configPath)
	prompter := &fakeScopePrompter{tty: true, accepted: false}
	application.ScopePrompter = prompter

	err := application.Run(context.Background(), RunOptions{
		Target:  "example.com",
		Profile: "passive",
		DryRun:  true,
	})
	if err == nil || !strings.Contains(err.Error(), "declined") {
		t.Fatalf("Run() error = %v, want declined confirmation", err)
	}
	if prompter.calls != 1 {
		t.Fatalf("prompt calls = %d, want 1", prompter.calls)
	}
	if _, err := os.Stat(filepath.Join(dir, "runs")); !os.IsNotExist(err) {
		t.Fatalf("run workspace should not be created after refusal; stat error = %v", err)
	}
}

func TestPlanShowsImplicitScopeWithoutConfirmationOrRun(t *testing.T) {
	dir := t.TempDir()
	configPath := writeTestConfig(t, dir)
	application := New(configPath)
	prompter := &fakeScopePrompter{tty: false}
	application.ScopePrompter = prompter

	plans, err := application.Plan(PlanOptions{
		Target:     "example.com",
		Profile:    "passive",
		ScopeMode:  "domain",
		Exclusions: []string{"admin.example.com"},
	})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if len(plans) != 1 {
		t.Fatalf("plan count = %d, want 1", len(plans))
	}
	plan := plans[0]
	if plan.ScopeSource != scopeSourceImplicit || plan.ScopeMode != "domain" {
		t.Fatalf("plan scope = source %q mode %q", plan.ScopeSource, plan.ScopeMode)
	}
	if prompter.calls != 0 {
		t.Fatalf("prompt calls = %d, want 0 for read-only plan", prompter.calls)
	}
	if _, err := os.Stat(filepath.Join(dir, "runs")); !os.IsNotExist(err) {
		t.Fatalf("plan should not create a run workspace; stat error = %v", err)
	}
}

func TestRunPersistsEffectiveScopeAndManifestMetadata(t *testing.T) {
	dir := t.TempDir()
	configPath := writeTestConfig(t, dir)
	application := New(configPath)

	err := application.Run(context.Background(), RunOptions{
		Target:       "example.com",
		Profile:      "passive",
		ScopeMode:    "domain",
		Exclusions:   []string{"admin.example.com"},
		ConfirmScope: true,
		DryRun:       true,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	manifests, err := filepath.Glob(filepath.Join(dir, "runs", "example.com", "*", "00_meta", "manifest.json"))
	if err != nil || len(manifests) != 1 {
		t.Fatalf("manifest files = %v, error = %v", manifests, err)
	}
	data, err := os.ReadFile(manifests[0])
	if err != nil {
		t.Fatal(err)
	}
	var manifest storage.RunManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.ScopePath != "00_meta/effective-scope.txt" ||
		manifest.ScopeSource != scopeSourceImplicit ||
		manifest.ScopeMode != "domain" {
		t.Fatalf("scope metadata = path %q source %q mode %q", manifest.ScopePath, manifest.ScopeSource, manifest.ScopeMode)
	}
	scopeData, err := os.ReadFile(filepath.Join(filepath.Dir(manifests[0]), "effective-scope.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(scopeData), "example.com\n*.example.com\n!admin.example.com\n"; got != want {
		t.Fatalf("effective scope = %q, want %q", got, want)
	}
}

func writeTestConfig(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "scanforge.yaml")
	contents := "workspace: " + filepath.Join(dir, "runs") + "\ndefault_scope: " + filepath.Join(dir, "missing-scope.txt") + "\n"
	if err := os.WriteFile(path, []byte(contents), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}
