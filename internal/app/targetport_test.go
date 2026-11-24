package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPlanShowsTargetPortHintWithHostOnlyScope(t *testing.T) {
	for _, target := range []string{"http://127.0.0.1:8082", "127.0.0.1:8082"} {
		t.Run(target, func(t *testing.T) {
			app := New(writeTestConfig(t, t.TempDir()))
			results, err := app.Plan(PlanOptions{Target: target, Profile: "web", ScopeMode: "exact"})
			if err != nil {
				t.Fatalf("Plan() error = %v", err)
			}
			got := results[0]
			if got.ProbeHint != "127.0.0.1:8082" {
				t.Fatalf("ProbeHint = %q", got.ProbeHint)
			}
			if strings.Join(got.ScopeEntries, ",") != "127.0.0.1" {
				t.Fatalf("scope entries = %v, want the host only (no port)", got.ScopeEntries)
			}
		})
	}
}

func TestPlanWithoutPortHasNoHint(t *testing.T) {
	app := New(writeTestConfig(t, t.TempDir()))
	results, err := app.Plan(PlanOptions{Target: "http://127.0.0.1", Profile: "web", ScopeMode: "exact"})
	if err != nil {
		t.Fatal(err)
	}
	if results[0].ProbeHint != "" {
		t.Fatalf("ProbeHint = %q, want none", results[0].ProbeHint)
	}
}

func TestTargetPortDoesNotWeakenScope(t *testing.T) {
	dir := t.TempDir()
	app := New(writeTestConfig(t, dir))

	// A port-scoped scope entry stays rejected.
	portScope := filepath.Join(dir, "port-scope.txt")
	if err := os.WriteFile(portScope, []byte("127.0.0.1:8082\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := app.Plan(PlanOptions{Target: "http://127.0.0.1:8082", Scope: portScope})
	if err == nil || !strings.Contains(err.Error(), "port-scoped entry") {
		t.Fatalf("port-scoped scope entry error = %v", err)
	}

	// The host must still be in the explicit scope, whatever the port.
	hostScope := filepath.Join(dir, "host-scope.txt")
	if err := os.WriteFile(hostScope, []byte("example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := app.Plan(PlanOptions{Target: "127.0.0.1:8082", Scope: hostScope}); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("out-of-scope host:port error = %v", err)
	}
	if _, err := app.Plan(PlanOptions{Target: "example.com:8443", Scope: hostScope}); err != nil {
		t.Fatalf("in-scope host with port hint rejected: %v", err)
	}

	// A malformed port is still rejected by the scope layer.
	if _, err := app.Plan(PlanOptions{Target: "example.com:99999", ScopeMode: "exact"}); err == nil {
		t.Fatal("invalid port accepted")
	}
}
