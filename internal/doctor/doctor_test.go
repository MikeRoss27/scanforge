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
		Profile: "safe",
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

func TestRunDNSBruteChecksTransitiveTools(t *testing.T) {
	cfg := config.Default()
	cfg.Profiles["dns-only"] = []string{"dnsbrute"}
	runner := New(mockToolChecker{})

	checks, _, err := runner.Run(context.Background(), Options{Profile: "dns-only", Config: cfg})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	seen := map[string]bool{}
	for _, check := range checks {
		seen[check.Name] = true
	}
	for _, name := range []string{"shuffledns", "massdns", "dns-wordlist"} {
		if !seen[name] {
			t.Errorf("expected %s to be checked for dnsbrute", name)
		}
	}
}

func TestRunOptionalChromiumDoesNotFail(t *testing.T) {
	cfg := config.Default()
	cfg.Profiles["browser-only"] = []string{"jsverify"}
	runner := New(mockToolChecker{results: map[string]Check{
		"chromium": {Name: "chromium", Status: SeverityFail, Message: "missing", Required: true},
	}})

	checks, exitCode, err := runner.Run(context.Background(), Options{Profile: "browser-only", Config: cfg})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("optional browser must not fail doctor, got exit code %d", exitCode)
	}
	if checks[0].Status != SeverityWarn || checks[0].Required {
		t.Fatalf("expected optional warning, got %+v", checks[0])
	}
}

func TestRunUnknownProfileReturnsError(t *testing.T) {
	_, _, err := New(mockToolChecker{}).Run(context.Background(), Options{
		Profile: "does-not-exist",
		Config:  config.Default(),
	})
	if err == nil {
		t.Fatal("expected unknown profile to return an error")
	}
}

func TestVersionMatches(t *testing.T) {
	for _, test := range []struct {
		message  string
		expected string
		matches  bool
	}{
		{"subfinder version v2.15.0", "2.15.0", true},
		{"httpx 1.10.0", "v1.10.0", true},
		{"WAFW00F \x1b[1;94mv2.4.2\x1b[0m", "2.4.2", true},
		{"nuclei v3.10.0", "3.11.0", false},
		{"unknown", "1.0.0", false},
	} {
		if got := versionMatches(test.message, test.expected); got != test.matches {
			t.Errorf("versionMatches(%q, %q) = %v", test.message, test.expected, got)
		}
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
