package app

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeWizardPrompter struct {
	tty          bool
	target       string
	profile      string
	targetCalls  int
	profileCalls int
}

func (p *fakeWizardPrompter) IsTTY() bool { return p.tty }

func (p *fakeWizardPrompter) AskTarget() (string, error) {
	p.targetCalls++
	return p.target, nil
}

func (p *fakeWizardPrompter) AskProfile(_ []string, current string) (string, error) {
	p.profileCalls++
	if p.profile == "" {
		return current, nil
	}
	return p.profile, nil
}

func TestRunWizardNotTriggeredOutsideTTY(t *testing.T) {
	dir := t.TempDir()
	application := New(filepath.Join(dir, "missing-config.yaml"))
	wizard := &fakeWizardPrompter{tty: false}
	application.Wizard = wizard

	err := application.Run(context.Background(), RunOptions{
		Profile: "passive",
		DryRun:  true,
	})
	if err == nil || !strings.Contains(err.Error(), "target is required") {
		t.Fatalf("Run() error = %v, want missing-target error", err)
	}
	if wizard.targetCalls != 0 || wizard.profileCalls != 0 {
		t.Fatalf("wizard calls = target %d profile %d, want 0", wizard.targetCalls, wizard.profileCalls)
	}
}

func TestRunWizardAsksMissingTargetAndProfile(t *testing.T) {
	dir := t.TempDir()
	application := New(writeTestConfig(t, dir))
	wizard := &fakeWizardPrompter{tty: true, target: "example.com", profile: "passive"}
	application.Wizard = wizard

	err := application.Run(context.Background(), RunOptions{
		DryRun:       true,
		ConfirmScope: true,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if wizard.targetCalls != 1 || wizard.profileCalls != 1 {
		t.Fatalf("wizard calls = target %d profile %d, want 1/1", wizard.targetCalls, wizard.profileCalls)
	}

	manifests, err := filepath.Glob(filepath.Join(dir, "runs", "example.com", "*", "00_meta", "manifest.json"))
	if err != nil || len(manifests) != 1 {
		t.Fatalf("manifest files = %v, error = %v", manifests, err)
	}
	data, err := os.ReadFile(manifests[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"profile": "passive"`) {
		t.Fatalf("manifest profile not taken from wizard: %s", data)
	}
}

func TestRunWizardAsksOnlyMissingProfile(t *testing.T) {
	dir := t.TempDir()
	application := New(writeTestConfig(t, dir))
	wizard := &fakeWizardPrompter{tty: true, profile: "ports"}
	application.Wizard = wizard

	err := application.Run(context.Background(), RunOptions{
		Target:       "example.com",
		DryRun:       true,
		ConfirmScope: true,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if wizard.targetCalls != 0 || wizard.profileCalls != 1 {
		t.Fatalf("wizard calls = target %d profile %d, want 0/1", wizard.targetCalls, wizard.profileCalls)
	}
}

func TestRunWizardSkipsQuestionsWhenEverythingProvided(t *testing.T) {
	dir := t.TempDir()
	application := New(writeTestConfig(t, dir))
	wizard := &fakeWizardPrompter{tty: true}
	application.Wizard = wizard

	err := application.Run(context.Background(), RunOptions{
		Target:       "example.com",
		Profile:      "passive",
		DryRun:       true,
		ConfirmScope: true,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if wizard.targetCalls != 0 || wizard.profileCalls != 0 {
		t.Fatalf("wizard calls = target %d profile %d, want 0", wizard.targetCalls, wizard.profileCalls)
	}
}

func TestRunWizardSkipsTargetWhenTargetsFileGiven(t *testing.T) {
	dir := t.TempDir()
	targetsPath := filepath.Join(dir, "targets.txt")
	if err := os.WriteFile(targetsPath, []byte("example.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	application := New(writeTestConfig(t, dir))
	wizard := &fakeWizardPrompter{tty: true, profile: "passive"}
	application.Wizard = wizard

	err := application.Run(context.Background(), RunOptions{
		TargetsFile:  targetsPath,
		DryRun:       true,
		ConfirmScope: true,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if wizard.targetCalls != 0 || wizard.profileCalls != 1 {
		t.Fatalf("wizard calls = target %d profile %d, want 0/1", wizard.targetCalls, wizard.profileCalls)
	}
}

func TestTerminalWizardAskTargetRetriesOnEmpty(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := w.WriteString("\nexample.com\n"); err != nil {
		t.Fatal(err)
	}
	p := &terminalWizardPrompter{input: r, output: &bytes.Buffer{}}

	target, err := p.AskTarget()
	if err != nil {
		t.Fatalf("AskTarget() error = %v", err)
	}
	if target != "example.com" {
		t.Fatalf("target = %q, want example.com", target)
	}
}

func TestTerminalWizardAskProfileByNumberAndDefault(t *testing.T) {
	available := []string{"safe", "recon", "passive", "web"}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := w.WriteString("4\n"); err != nil {
		t.Fatal(err)
	}
	p := &terminalWizardPrompter{input: r, output: &bytes.Buffer{}}

	got, err := p.AskProfile(available, "passive")
	if err != nil {
		t.Fatalf("AskProfile() error = %v", err)
	}
	if got != "web" {
		t.Fatalf("profile = %q, want web", got)
	}
}

func TestTerminalWizardAskProfileEmptyAnswerUsesDefault(t *testing.T) {
	available := []string{"safe", "passive"}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := w.WriteString("\n"); err != nil {
		t.Fatal(err)
	}
	p := &terminalWizardPrompter{input: r, output: &bytes.Buffer{}}

	got, err := p.AskProfile(available, "passive")
	if err != nil {
		t.Fatalf("AskProfile() error = %v", err)
	}
	if got != "passive" {
		t.Fatalf("profile = %q, want passive", got)
	}
}
