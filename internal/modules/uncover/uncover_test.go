package uncover

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/auth"
	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

// withAuthHome points internal/auth.DefaultPath() at a throwaway HOME for
// the duration of the test, so these tests never read or write the
// developer's real ~/.scanforge/auth.yaml.
func withAuthHome(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // Windows equivalent of HOME
}

func newRun(t *testing.T) *storage.Run {
	t.Helper()
	root := t.TempDir()
	for _, d := range []string{"00_meta", "03_ports"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0755); err != nil {
			t.Fatal(err)
		}
	}
	return &storage.Run{RootDir: root, MetaDir: filepath.Join(root, "00_meta"), CommandsLog: filepath.Join(root, "00_meta", "commands.log")}
}

func TestRunSkipsWithoutConfiguredAPIKey(t *testing.T) {
	withAuthHome(t)
	run := newRun(t)
	runCtx := modules.NewRunContext("example.com", "recon", false, run)

	res, err := New("uncover-test").Run(context.Background(), runCtx, runner.NewDryRunExecutor(false))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !modules.IsNotApplicable(res) {
		t.Fatalf("expected a skip when no provider key is configured, got %+v", res)
	}
	if _, ok := runCtx.GetArtifact(artifactName); !ok {
		t.Fatal("uncover_hosts must still be published (empty) so the DAG proceeds")
	}
}

func TestRunDryRunRecordsCommandWithoutExecution(t *testing.T) {
	withAuthHome(t)
	cfg, err := auth.Load()
	if err != nil {
		t.Fatal(err)
	}
	cfg.SetKey("shodan", "test-key")
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}

	run := newRun(t)
	runCtx := modules.NewRunContext("example.com", "recon", true, run)

	res, err := New("uncover-test").Run(context.Background(), runCtx, runner.NewDryRunExecutor(false))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Status != "completed" {
		t.Fatalf("status = %q, want completed", res.Status)
	}

	log, err := os.ReadFile(run.CommandsLog)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(log), "uncover-test") || !strings.Contains(string(log), "shodan") {
		t.Fatalf("planned command not recorded: %q", log)
	}
	if _, ok := runCtx.GetArtifact(artifactName); !ok {
		t.Fatal("uncover_hosts must be published even in dry run")
	}
}

func TestRunSkipsIPTarget(t *testing.T) {
	withAuthHome(t)
	cfg, err := auth.Load()
	if err != nil {
		t.Fatal(err)
	}
	cfg.SetKey("censys", "test-key")
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}

	run := newRun(t)
	runCtx := modules.NewRunContext("203.0.113.9", "recon", false, run)
	res, err := New("uncover-test").Run(context.Background(), runCtx, runner.NewDryRunExecutor(false))
	if err != nil || !modules.IsNotApplicable(res) {
		t.Fatalf("IP target should be skipped: %+v %v", res, err)
	}
}

func TestConfiguredEnginesFiltersUnknownProvidersAndSorts(t *testing.T) {
	cfg := &auth.AuthConfig{Providers: map[string]map[string]string{
		"zoomeye": {"api_key": "z"},
		"shodan":  {"api_key": "s"},
		"chaos":   {"api_key": "c"}, // not an uncover engine name, must be dropped
		"fofa":    {"api_key": ""},  // empty key, must be dropped
	}}
	got := configuredEngines(cfg)
	want := []string{"shodan", "zoomeye"}
	if len(got) != len(want) {
		t.Fatalf("configuredEngines = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("configuredEngines = %v, want %v", got, want)
		}
	}
}

func TestParseHostPortsPrefersHostDedupsAndCaps(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "raw.jsonl")
	lines := []string{
		`{"ip":"203.0.113.9","port":443,"host":"app.example.com"}`,
		`{"ip":"203.0.113.9","port":443,"host":"app.example.com"}`, // duplicate
		`{"ip":"203.0.113.10","port":8080}`,                        // no host, falls back to ip
		`not json`,
		`{"ip":"203.0.113.11","port":0}`, // invalid port, dropped
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	hosts, capped, err := parseHostPorts(path, 500)
	if err != nil {
		t.Fatal(err)
	}
	if capped {
		t.Fatal("did not expect capping")
	}
	want := []string{"203.0.113.10:8080", "app.example.com:443"}
	if len(hosts) != len(want) {
		t.Fatalf("parseHostPorts = %v, want %v", hosts, want)
	}
	for i := range want {
		if hosts[i] != want[i] {
			t.Fatalf("parseHostPorts = %v, want %v", hosts, want)
		}
	}
}

func TestParseHostPortsCapsAtMax(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "raw.jsonl")
	var lines []string
	for i := 1; i <= 10; i++ {
		lines = append(lines, `{"ip":"203.0.113.`+strconv.Itoa(i)+`","port":80}`)
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	hosts, capped, err := parseHostPorts(path, 3)
	if err != nil {
		t.Fatal(err)
	}
	if !capped {
		t.Fatal("expected capping to be reported")
	}
	if len(hosts) != 3 {
		t.Fatalf("parseHostPorts returned %d hosts, want cap of 3", len(hosts))
	}
}

func TestParseHostPortsMissingFileYieldsEmpty(t *testing.T) {
	hosts, capped, err := parseHostPorts(filepath.Join(t.TempDir(), "missing.jsonl"), 500)
	if err != nil {
		t.Fatal(err)
	}
	if capped || len(hosts) != 0 {
		t.Fatalf("expected no hosts for a missing file, got %v capped=%v", hosts, capped)
	}
}
