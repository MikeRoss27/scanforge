package doctor

import (
	"context"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/config"
)

type mockToolChecker struct {
	results map[string]Check
}

func (m mockToolChecker) CheckTool(ctx context.Context, name, binary string, verbose bool) Check {
	if check, ok := m.results[name]; ok {
		return check
	}

	return Check{
		Name:     name,
		Status:   SeverityOK,
		Message:  binary,
		Required: true,
	}
}

func TestRunAllToolsOK(t *testing.T) {
	runner := New(mockToolChecker{
		results: map[string]Check{
			"subfinder": {Name: "subfinder", Status: SeverityOK, Message: "ok", Required: true},
			"httpx":     {Name: "httpx", Status: SeverityOK, Message: "ok", Required: true},
			"nuclei":    {Name: "nuclei", Status: SeverityOK, Message: "ok", Required: true},
		},
	})

	checks, exitCode, err := runner.Run(context.Background(), Options{
		Profile: "web",
		Config:  config.Default(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	if len(checks) < 5 {
		t.Fatalf("expected at least 5 checks, got %d", len(checks))
	}
}

func TestRunMissingToolFails(t *testing.T) {
	runner := New(mockToolChecker{
		results: map[string]Check{
			"subfinder": {Name: "subfinder", Status: SeverityOK, Message: "ok", Required: true},
			"httpx":     {Name: "httpx", Status: SeverityFail, Message: "missing", Required: true},
		},
	})

	_, exitCode, err := runner.Run(context.Background(), Options{
		Profile: "passive",
		Config:  config.Default(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}
}

func TestRunPassiveSkipsNuclei(t *testing.T) {
	checked := map[string]bool{}

	runner := New(mockToolChecker{
		results: map[string]Check{
			"subfinder": {Name: "subfinder", Status: SeverityOK, Message: "ok", Required: true},
			"httpx":     {Name: "httpx", Status: SeverityOK, Message: "ok", Required: true},
		},
	})

	checks, exitCode, err := runner.Run(context.Background(), Options{
		Profile: "passive",
		Config:  config.Default(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, check := range checks {
		checked[check.Name] = true
	}

	if checked["nuclei"] {
		t.Fatal("expected nuclei check to be skipped for passive profile")
	}

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}
}

func TestFormatChecksJSON(t *testing.T) {
	output, err := FormatChecksJSON([]Check{
		{Name: "subfinder", Status: SeverityOK, Message: "ok", Required: true},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if output == "" {
		t.Fatal("expected json output")
	}
}
