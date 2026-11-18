package app

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/config"
	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/modules/dnsx"
	"github.com/MikeRoss27/scanforge/internal/modules/httpx"
	"github.com/MikeRoss27/scanforge/internal/modules/subfinder"
	"github.com/MikeRoss27/scanforge/internal/orchestrator"
	"github.com/MikeRoss27/scanforge/internal/runner"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

func TestDefaultScopeIncludesDiscoveredSubdomains(t *testing.T) {
	for _, tt := range []struct {
		target, mode, wantMode string
		wantEntries            []string
	}{
		{"https://Example.COM/path", "", "domain", []string{"example.com", "*.example.com"}},
		{"api.example.com", "", "domain", []string{"api.example.com", "*.api.example.com"}},
		{"example.com", "exact", "exact", []string{"example.com"}},
		{"192.0.2.1", "", "exact", []string{"192.0.2.1"}},
		{"https://[2001:db8::1]/", "", "exact", []string{"2001:db8::1"}},
		{"localhost", "", "exact", []string{"localhost"}},
	} {
		t.Run(tt.target+"/"+tt.mode, func(t *testing.T) {
			cfg := config.Default()
			cfg.DefaultScope = ""
			resolved, err := resolveScope(cfg, tt.target, "", tt.mode, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if resolved.proposal.Mode != tt.wantMode || !reflect.DeepEqual(resolved.proposal.Entries, tt.wantEntries) {
				t.Fatalf("unexpected scope: %+v", resolved.proposal)
			}
		})
	}
}

// discoveryExecutor simulates tools from their actual input files, so a lost
// subdomain cannot reappear downstream through a canned tool response.
type discoveryExecutor struct{}

func (discoveryExecutor) Run(_ context.Context, command runner.Command) (*runner.CommandResult, error) {
	output := "api.example.com\nadmin.example.com\noutside.test\n"
	if command.Name != "subfinder" {
		if len(command.Args) < 2 || command.Args[0] != "-l" {
			return nil, fmt.Errorf("missing input list for %s", command.Name)
		}
		input, err := os.ReadFile(command.Args[1])
		if err != nil {
			return nil, err
		}
		var records strings.Builder
		for _, host := range strings.Fields(string(input)) {
			record := map[string]string{"host": host}
			if command.Name == "httpx" {
				record = map[string]string{"url": "https://" + host}
			}
			data, err := json.Marshal(record)
			if err != nil {
				return nil, err
			}
			records.Write(data)
			records.WriteByte('\n')
		}
		output = records.String()
	}
	if err := os.WriteFile(command.StdoutFile, []byte(output), 0644); err != nil {
		return nil, err
	}
	return &runner.CommandResult{Command: command}, nil
}

func TestDiscoveryAutomaticallyFeedsDownstreamModules(t *testing.T) {
	cfg := config.Default()
	cfg.DefaultScope = ""
	cfg.Profiles["test"] = []string{"subfinder", "dnsx", "httpx"}
	resolved, err := resolveScope(cfg, "https://example.com/", "", "", nil, []string{"admin.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	run, err := storage.NewRunStore(t.TempDir()).Create("example.com")
	if err != nil {
		t.Fatal(err)
	}
	registry := modules.NewRegistry()
	registry.Register(subfinder.New(""))
	registry.Register(dnsx.New(""))
	registry.Register(httpx.New(""))
	results, err := orchestrator.New(discoveryExecutor{}, registry).Run(context.Background(), run, orchestrator.Options{
		Target: "https://example.com/", Profile: "test", Config: cfg, Scope: resolved.value,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 3 {
		t.Fatalf("completed %d modules, want 3", len(results))
	}
	for _, result := range results {
		if result.Status != "completed" {
			t.Fatalf("%s status = %q", result.Name, result.Status)
		}
	}
	alive, err := os.ReadFile(run.Path("02_http", "alive.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(alive) != "https://api.example.com\nhttps://example.com\n" {
		t.Fatalf("discovered subdomain did not propagate, or excluded hosts leaked: %q", alive)
	}
}
