package app

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestApplyWordPressAppendsChain(t *testing.T) {
	names := []string{"subfinder", "dnsx", "httpx"}
	got := applyWordPress(names, true, false)
	want := append(append([]string{}, names...), wordPressChain...)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("applyWordPress(...) = %v, want %v", got, want)
	}
}

func TestApplyWordPressDeduplicates(t *testing.T) {
	names := []string{"httpx", "wpdetect", "wpplugins"}
	got := applyWordPress(names, true, true)
	seen := map[string]int{}
	for _, name := range got {
		seen[name]++
	}
	for name, count := range seen {
		if count > 1 {
			t.Fatalf("module %q duplicated in %v", name, got)
		}
	}
	if _, ok := seen["wpbrute"]; !ok {
		t.Fatalf("expected wpbrute to be appended with bruteforce=true, got %v", got)
	}
	if _, ok := seen["wpdetect"]; !ok {
		t.Fatalf("expected wpdetect exactly once, got %v", got)
	}
}

func TestApplyWordPressDisabled(t *testing.T) {
	names := []string{"httpx"}
	got := applyWordPress(names, false, false)
	if !reflect.DeepEqual(got, names) {
		t.Fatalf("applyWordPress(...) with --wp=false = %v, want %v", got, names)
	}
}

func TestApplyWordPressBruteforceAddsWpbrute(t *testing.T) {
	got := applyWordPress([]string{"httpx"}, false, true)
	want := []string{"httpx", "wpbrute"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("applyWordPress(...) = %v, want %v", got, want)
	}
}

// TestWPFlagReachesTheOrchestratorOnANonWPProfile is a regression test for a
// bug where --wp on top of any profile other than the "wp" preset had zero
// effect on the actual scan: prepareRun computed the WP-adjusted module list
// (applyWordPress) only to use it for the intro's module count, while
// execute() handed the orchestrator just Profile+Config, which re-resolved
// the *unadjusted* profile from scratch and silently dropped the chain. Only
// `--preset wp` ever worked, because that profile's module list already
// includes the chain statically; `--profile X --wp` for any other X did not.
// This locks that the chain survives the full prepareRun -> execute path,
// not just applyWordPress in isolation (see TestApplyWordPressAppendsChain
// above, which alone would never have caught this).
func TestWPFlagReachesTheOrchestratorOnANonWPProfile(t *testing.T) {
	root := t.TempDir()
	app := New(writeTestConfig(t, root))

	err := app.Run(context.Background(), RunOptions{
		Target:       "example.com",
		Profile:      "passive", // deliberately not the "wp" preset
		WP:           true,
		DryRun:       true,
		ConfirmScope: true,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	runs, err := os.ReadDir(filepath.Join(root, "runs", "example.com"))
	if err != nil || len(runs) != 1 {
		t.Fatalf("expected one run directory, got %v (err=%v)", runs, err)
	}
	manifestData, err := os.ReadFile(filepath.Join(root, "runs", "example.com", runs[0].Name(), "00_meta", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	manifest := string(manifestData)
	for _, module := range wordPressChain {
		if !strings.Contains(manifest, `"name": "`+module+`"`) {
			t.Errorf("manifest is missing WordPress chain module %q — --wp did not reach the orchestrator:\n%s", module, manifest)
		}
	}
}

func TestApplyWordPressAppendsWithoutWPButBruteforce(t *testing.T) {
	// wp preset without --wp resolves to the chain through the profile, but
	// --wp-bruteforce must still layer wpbrute on top.
	got := applyWordPress([]string{"wpdetect", "wpplugins", "whatever"}, false, true)
	if got[len(got)-1] != "wpbrute" {
		t.Fatalf("expected wpbrute appended, got %v", got)
	}
}
