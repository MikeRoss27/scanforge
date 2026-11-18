package app

import (
	"reflect"
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

func TestApplyWordPressAppendsWithoutWPButBruteforce(t *testing.T) {
	// wp preset without --wp resolves to the chain through the profile, but
	// --wp-bruteforce must still layer wpbrute on top.
	got := applyWordPress([]string{"wpdetect", "wpplugins", "whatever"}, false, true)
	if got[len(got)-1] != "wpbrute" {
		t.Fatalf("expected wpbrute appended, got %v", got)
	}
}
