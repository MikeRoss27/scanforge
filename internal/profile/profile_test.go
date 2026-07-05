package profile

import (
	"testing"
)

func TestResolveBuiltin(t *testing.T) {
	modules, err := Resolve("web", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(modules) == 0 {
		t.Fatal("expected modules for built-in profile")
	}
}

func TestResolveOverride(t *testing.T) {
	overrides := map[string][]string{
		"web": {"custom"},
	}
	modules, err := Resolve("web", overrides)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(modules) != 1 || modules[0] != "custom" {
		t.Fatal("expected overridden profile")
	}
}

func TestResolveUnknown(t *testing.T) {
	_, err := Resolve("unknown", nil)
	if err == nil {
		t.Fatal("expected error for unknown profile")
	}
}
