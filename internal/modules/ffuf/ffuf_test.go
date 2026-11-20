package ffuf

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

type recordingExecutor struct {
	commands []runner.Command
}

func (e *recordingExecutor) Run(_ context.Context, command runner.Command) (*runner.CommandResult, error) {
	e.commands = append(e.commands, command)
	return &runner.CommandResult{Command: command, ExitCode: 0}, nil
}

// fakeFfufExecutor records commands like recordingExecutor, but also writes
// a minimal ffuf-shaped JSON document to each command's "-o" path, so tests
// can exercise the per-host merge step.
type fakeFfufExecutor struct {
	mu       sync.Mutex
	commands []runner.Command
	// resultsFor maps a host (matched by substring of "-u") to the result
	// URLs it should report; hosts with no entry get zero results.
	resultsFor map[string][]string
}

func (e *fakeFfufExecutor) Run(_ context.Context, command runner.Command) (*runner.CommandResult, error) {
	e.mu.Lock()
	e.commands = append(e.commands, command)
	e.mu.Unlock()

	var outputPath, target string
	for i, arg := range command.Args {
		if arg == "-o" && i+1 < len(command.Args) {
			outputPath = command.Args[i+1]
		}
		if arg == "-u" && i+1 < len(command.Args) {
			target = command.Args[i+1]
		}
	}
	var results []map[string]any
	for host, urls := range e.resultsFor {
		if !strings.Contains(target, host) {
			continue
		}
		for _, u := range urls {
			results = append(results, map[string]any{"url": u, "host": host, "status": 200, "length": 123})
		}
	}
	doc, _ := json.Marshal(map[string]any{"results": results})
	if outputPath != "" {
		_ = os.WriteFile(outputPath, doc, 0644)
	}
	return &runner.CommandResult{Command: command, ExitCode: 0}, nil
}

func testRun(t *testing.T, root string) *storage.Run {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, "00_meta"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "02_http"), 0755); err != nil {
		t.Fatal(err)
	}
	return &storage.Run{RootDir: root, CommandsLog: filepath.Join(root, "00_meta", "commands.log")}
}

func TestRequiresAliveURLs(t *testing.T) {
	if got, want := New("").Requires(), []string{"alive_urls"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Requires() = %v, want %v", got, want)
	}
}

func TestRunBuildsFFUFCommand(t *testing.T) {
	// DryRun skips the wordlist existence check so the test runs anywhere.
	run := testRun(t, t.TempDir())
	inputPath := run.Path("02_http", "httpx.txt")
	if err := os.WriteFile(inputPath, []byte("http://example.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	runCtx := modules.NewRunContext("example.com", "web", true, run)
	if err := runCtx.AddArtifact("alive_urls", modules.Artifact{Name: "alive_urls", Type: "text", Path: "02_http/httpx.txt"}); err != nil {
		t.Fatal(err)
	}
	executor := &recordingExecutor{}

	result, err := New("ffuf-test").Run(context.Background(), runCtx, executor)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Status != "completed" {
		t.Fatalf("status = %q, want completed", result.Status)
	}
	if len(executor.commands) != 1 {
		t.Fatalf("got %d commands, want 1 (one per alive host)", len(executor.commands))
	}
	cmd := executor.commands[0]
	if cmd.Name != "ffuf-test" {
		t.Fatalf("command name = %q", cmd.Name)
	}
	args := strings.Join(cmd.Args, " ")
	// Each host gets its own -u target instead of a combined ":URL"
	// wordlist: ffuf's -ac auto-calibration only reliably learns a host's
	// soft-404/wildcard signature against a single -u target.
	for _, want := range []string{"-w", ":FUZZ", "-u", "http://example.com/FUZZ", "-o", run.Path("05_content", "ffuf", "host-0001.json"), "-of", "json", "-mc", "200,301,302,403", "-ac"} {
		if !strings.Contains(args, want) {
			t.Errorf("args %q missing %q", args, want)
		}
	}
	if strings.Contains(args, ":URL") || strings.Contains(args, "-ach") {
		t.Errorf("single-host run should not use the combined :URL wordlist or -ach: %q", args)
	}
	if _, ok := runCtx.GetArtifact("discovered_paths"); !ok {
		t.Fatal("discovered_paths artifact was not published")
	}
}

func TestRunAppliesWordlistAndFilterCodes(t *testing.T) {
	run := testRun(t, t.TempDir())
	if err := os.WriteFile(run.Path("02_http", "httpx.txt"), []byte("http://example.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	wordlist := filepath.Join(t.TempDir(), "custom.txt")
	if err := os.WriteFile(wordlist, []byte("admin\napi\n"), 0644); err != nil {
		t.Fatal(err)
	}
	runCtx := modules.NewRunContext("example.com", "web", false, run)
	if err := runCtx.AddArtifact("alive_urls", modules.Artifact{Name: "alive_urls", Type: "text", Path: "02_http/httpx.txt"}); err != nil {
		t.Fatal(err)
	}
	runCtx.Ffuf = modules.FfufOptions{Wordlist: wordlist, FilterCodes: "404,500"}
	executor := &recordingExecutor{}

	if _, err := New("ffuf").Run(context.Background(), runCtx, executor); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	args := strings.Join(executor.commands[0].Args, " ")
	for _, want := range []string{"-w", wordlist + ":FUZZ", "-fc", "404,500"} {
		if !strings.Contains(args, want) {
			t.Errorf("args %q missing %q", args, want)
		}
	}
}

func TestRunRequiresExistingWordlistOutsideDryRun(t *testing.T) {
	original := defaultWordlistCandidates
	t.Cleanup(func() { defaultWordlistCandidates = original })
	defaultWordlistCandidates = []string{filepath.Join(t.TempDir(), "nope.txt")}

	run := testRun(t, t.TempDir())
	if err := os.WriteFile(run.Path("02_http", "httpx.txt"), []byte("http://example.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	runCtx := modules.NewRunContext("example.com", "web", false, run)
	if err := runCtx.AddArtifact("alive_urls", modules.Artifact{Name: "alive_urls", Type: "text", Path: "02_http/httpx.txt"}); err != nil {
		t.Fatal(err)
	}
	if _, err := New("ffuf").Run(context.Background(), runCtx, &recordingExecutor{}); err == nil {
		t.Fatal("expected error for missing wordlist outside dry-run")
	}
}

func TestRunUsesDefaultWordlistWhenAvailable(t *testing.T) {
	original := defaultWordlistCandidates
	t.Cleanup(func() { defaultWordlistCandidates = original })

	wordlist := filepath.Join(t.TempDir(), "common.txt")
	if err := os.WriteFile(wordlist, []byte("admin\n"), 0644); err != nil {
		t.Fatal(err)
	}
	defaultWordlistCandidates = []string{filepath.Join(t.TempDir(), "missing.txt"), wordlist}

	run := testRun(t, t.TempDir())
	if err := os.WriteFile(run.Path("02_http", "httpx.txt"), []byte("http://example.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	runCtx := modules.NewRunContext("example.com", "web", false, run)
	if err := runCtx.AddArtifact("alive_urls", modules.Artifact{Name: "alive_urls", Type: "text", Path: "02_http/httpx.txt"}); err != nil {
		t.Fatal(err)
	}
	executor := &recordingExecutor{}

	if _, err := New("ffuf").Run(context.Background(), runCtx, executor); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	args := strings.Join(executor.commands[0].Args, " ")
	if !strings.Contains(args, "-w "+wordlist+":FUZZ") {
		t.Errorf("args %q should use auto-detected wordlist %q", args, wordlist)
	}
}

func TestResolveWordlistPicksFirstExistingCandidate(t *testing.T) {
	original := defaultWordlistCandidates
	t.Cleanup(func() { defaultWordlistCandidates = original })

	dir := t.TempDir()
	first := filepath.Join(dir, "missing.txt")
	second := filepath.Join(dir, "existing.txt")
	if err := os.WriteFile(second, []byte("admin\n"), 0644); err != nil {
		t.Fatal(err)
	}
	defaultWordlistCandidates = []string{first, second}

	if got, want := resolveWordlist(""), second; got != want {
		t.Fatalf("resolveWordlist(\"\") = %q, want %q", got, want)
	}
}

func TestResolveWordlistExpandsTilde(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := expandPath("~/file.txt"), filepath.Join(home, "file.txt"); got != want {
		t.Fatalf("expandPath(\"~/file.txt\") = %q, want %q", got, want)
	}
}

func TestResolveWordlistNoneExistingReturnsEmpty(t *testing.T) {
	original := defaultWordlistCandidates
	t.Cleanup(func() { defaultWordlistCandidates = original })
	defaultWordlistCandidates = []string{filepath.Join(t.TempDir(), "nope.txt")}

	if got := resolveWordlist(""); got != "" {
		t.Fatalf("resolveWordlist(\"\") = %q, want empty", got)
	}
}

func TestRunErrorListsWordlistCandidates(t *testing.T) {
	original := defaultWordlistCandidates
	t.Cleanup(func() { defaultWordlistCandidates = original })
	defaultWordlistCandidates = []string{filepath.Join(t.TempDir(), "nope.txt")}

	run := testRun(t, t.TempDir())
	if err := os.WriteFile(run.Path("02_http", "httpx.txt"), []byte("http://example.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	runCtx := modules.NewRunContext("example.com", "web", false, run)
	if err := runCtx.AddArtifact("alive_urls", modules.Artifact{Name: "alive_urls", Type: "text", Path: "02_http/httpx.txt"}); err != nil {
		t.Fatal(err)
	}
	_, err := New("ffuf").Run(context.Background(), runCtx, &recordingExecutor{})
	if err == nil {
		t.Fatal("expected error when no wordlist is available")
	}
	if !strings.Contains(err.Error(), "--ffuf-wordlist") {
		t.Fatalf("error %q should suggest --ffuf-wordlist", err)
	}
}

// TestRunFansOutOnePerHostAndMergesResults locks the fix for ffuf's -ac
// auto-calibration not holding when one invocation fuzzes several hosts
// through a combined ":URL" wordlist: each alive host must get its own
// ffuf process (so calibration is per host, not shared/broken), and the
// discovered_paths artifact must still be the union of every host's hits.
func TestRunFansOutOnePerHostAndMergesResults(t *testing.T) {
	run := testRun(t, t.TempDir())
	hosts := "https://a.example.com\nhttps://b.example.com\n"
	if err := os.WriteFile(run.Path("02_http", "httpx.txt"), []byte(hosts), 0644); err != nil {
		t.Fatal(err)
	}
	wordlist := filepath.Join(t.TempDir(), "words.txt")
	if err := os.WriteFile(wordlist, []byte("admin\n"), 0644); err != nil {
		t.Fatal(err)
	}
	runCtx := modules.NewRunContext("example.com", "web", false, run)
	if err := runCtx.AddArtifact("alive_urls", modules.Artifact{Name: "alive_urls", Type: "text", Path: "02_http/httpx.txt"}); err != nil {
		t.Fatal(err)
	}
	runCtx.Ffuf = modules.FfufOptions{Wordlist: wordlist}
	executor := &fakeFfufExecutor{resultsFor: map[string][]string{
		"a.example.com": {"https://a.example.com/admin"},
		"b.example.com": {"https://b.example.com/admin"},
	}}

	result, err := New("ffuf").Run(context.Background(), runCtx, executor)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Status != "completed" {
		t.Fatalf("status = %q, want completed", result.Status)
	}
	if len(executor.commands) != 2 {
		t.Fatalf("got %d ffuf processes, want 2 (one per host)", len(executor.commands))
	}
	for _, cmd := range executor.commands {
		args := strings.Join(cmd.Args, " ")
		if strings.Contains(args, ":URL") {
			t.Errorf("per-host command still uses the combined :URL wordlist: %q", args)
		}
	}

	merged, err := os.ReadFile(run.Path("05_content", "ffuf.json"))
	if err != nil {
		t.Fatalf("merged output missing: %v", err)
	}
	var doc struct {
		Results []struct {
			URL string `json:"url"`
		} `json:"results"`
	}
	if err := json.Unmarshal(merged, &doc); err != nil {
		t.Fatalf("merged output is not valid JSON: %v", err)
	}
	if len(doc.Results) != 2 {
		t.Fatalf("merged results = %d, want 2 (one per host): %+v", len(doc.Results), doc.Results)
	}
	var urls []string
	for _, r := range doc.Results {
		urls = append(urls, r.URL)
	}
	for _, want := range []string{"https://a.example.com/admin", "https://b.example.com/admin"} {
		found := false
		for _, u := range urls {
			if u == want {
				found = true
			}
		}
		if !found {
			t.Errorf("merged results missing %q: %+v", want, urls)
		}
	}
}

// TestRunReportsProgressPerHost locks the fix for ffuf looking "stalled" for
// however long its slowest host takes: ffuf's own JSON writer only flushes
// once a whole host's wordlist pass is done, so nothing else gives the
// operator forward motion — each finished host must advance the progress
// line instead of leaving it flat until every host is done.
func TestRunReportsProgressPerHost(t *testing.T) {
	run := testRun(t, t.TempDir())
	hosts := "https://a.example.com\nhttps://b.example.com\nhttps://c.example.com\n"
	if err := os.WriteFile(run.Path("02_http", "httpx.txt"), []byte(hosts), 0644); err != nil {
		t.Fatal(err)
	}
	wordlist := filepath.Join(t.TempDir(), "words.txt")
	if err := os.WriteFile(wordlist, []byte("admin\n"), 0644); err != nil {
		t.Fatal(err)
	}
	runCtx := modules.NewRunContext("example.com", "web", false, run)
	if err := runCtx.AddArtifact("alive_urls", modules.Artifact{Name: "alive_urls", Type: "text", Path: "02_http/httpx.txt"}); err != nil {
		t.Fatal(err)
	}
	runCtx.Ffuf = modules.FfufOptions{Wordlist: wordlist}

	var mu sync.Mutex
	var updates []modules.ModuleProgressEvent
	runCtx.SetProgressSink(func(e modules.ModuleProgressEvent) {
		mu.Lock()
		updates = append(updates, e)
		mu.Unlock()
	})

	if _, err := New("ffuf").Run(context.Background(), runCtx, &fakeFfufExecutor{}); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(updates) != 3 {
		t.Fatalf("got %d progress updates, want 3 (one per host): %+v", len(updates), updates)
	}
	seen := map[int]bool{}
	for _, u := range updates {
		if u.Name != "ffuf" || u.Total != 3 || u.Unit != "hosts" {
			t.Errorf("unexpected progress event: %+v", u)
		}
		seen[u.Current] = true
	}
	for _, want := range []int{1, 2, 3} {
		if !seen[want] {
			t.Errorf("missing progress update for Current=%d: %+v", want, updates)
		}
	}
}

// TestRunDryRunMissingInputPublishesEmptyArtifact mirrors nmap's dry-run
// handling: a dry run never actually executes anything, so an upstream
// module's declared artifact can point at a file that was never written.
// ffuf must not fail the whole pipeline over that — it publishes an empty
// discovered_paths artifact and moves on, same as nmap does for open_ports.
func TestRunDryRunMissingInputPublishesEmptyArtifact(t *testing.T) {
	run := testRun(t, t.TempDir())
	runCtx := modules.NewRunContext("example.com", "web", true, run)
	if err := runCtx.AddArtifact("alive_urls", modules.Artifact{Name: "alive_urls", Type: "text", Path: "02_http/httpx.txt"}); err != nil {
		t.Fatal(err)
	}

	result, err := New("ffuf").Run(context.Background(), runCtx, &recordingExecutor{})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Status != "completed" {
		t.Fatalf("status = %q, want completed", result.Status)
	}
	if _, ok := runCtx.GetArtifact("discovered_paths"); !ok {
		t.Fatal("discovered_paths artifact was not published")
	}
}
