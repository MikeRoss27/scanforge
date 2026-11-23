package ffuf

import (
	"context"
	"encoding/json"
	"fmt"
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

func TestRunAppliesWAFBypassWhenWAFDetected(t *testing.T) {
	run := testRun(t, t.TempDir())
	inputPath := run.Path("02_http", "httpx.txt")
	if err := os.WriteFile(inputPath, []byte("http://example.com\nhttp://other.example.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	runCtx := modules.NewRunContext("example.com", "web", true, run)
	if err := runCtx.AddArtifact("alive_urls", modules.Artifact{Name: "alive_urls", Type: "text", Path: "02_http/httpx.txt"}); err != nil {
		t.Fatal(err)
	}
	runCtx.SetWAFInfo(modules.WAFInfo{Detected: true, Names: []string{"Cloudflare"}})
	executor := &recordingExecutor{}

	if _, err := New("ffuf-test").Run(context.Background(), runCtx, executor); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(executor.commands) != 2 {
		t.Fatalf("got %d commands, want 2", len(executor.commands))
	}
	for _, cmd := range executor.commands {
		args := strings.Join(cmd.Args, " ")
		if !strings.Contains(args, "-p 0.4-1.6") {
			t.Errorf("args %q missing WAF throttle flag", args)
		}
		if !strings.Contains(args, "-H User-Agent:") {
			t.Errorf("args %q missing rotated User-Agent header", args)
		}
	}
}

func TestRunKeepsOperatorUserAgentDespiteWAF(t *testing.T) {
	run := testRun(t, t.TempDir())
	inputPath := run.Path("02_http", "httpx.txt")
	if err := os.WriteFile(inputPath, []byte("http://example.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	runCtx := modules.NewRunContext("example.com", "web", true, run)
	if err := runCtx.AddArtifact("alive_urls", modules.Artifact{Name: "alive_urls", Type: "text", Path: "02_http/httpx.txt"}); err != nil {
		t.Fatal(err)
	}
	runCtx.SetWAFInfo(modules.WAFInfo{Detected: true})
	runCtx.Headers = []string{"User-Agent: my-custom-agent"}
	executor := &recordingExecutor{}

	if _, err := New("ffuf-test").Run(context.Background(), runCtx, executor); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	args := strings.Join(executor.commands[0].Args, " ")
	if strings.Count(args, "User-Agent:") != 1 {
		t.Errorf("args %q should carry exactly the operator's User-Agent, no rotated one added: %d occurrences", args, strings.Count(args, "User-Agent:"))
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

// ffufResult builds one ffuf-shaped result record.
func ffufResult(url string, status, length, words int) json.RawMessage {
	raw, _ := json.Marshal(map[string]any{"url": url, "status": status, "length": length, "words": words})
	return raw
}

// wafFlood reproduces the real voltlaunchr.com case: a WAF answering every
// wordlist entry with the same 403 block page (25103 bytes, 1053 words)
// that ffuf's -ac calibration failed to filter.
func wafFlood(host string, n int) []json.RawMessage {
	out := make([]json.RawMessage, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, ffufResult(fmt.Sprintf("%s/word%04d", host, i), 403, 25103, 1053))
	}
	return out
}

func identicalResults(host string, n, status, length int) []json.RawMessage {
	out := make([]json.RawMessage, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, ffufResult(fmt.Sprintf("%s/x%d-%d", host, status, i), status, length, 7))
	}
	return out
}

func variedResults(host string, n int) []json.RawMessage {
	out := make([]json.RawMessage, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, ffufResult(fmt.Sprintf("%s/p%d", host, i), 200, 1000+i, 50+i))
	}
	return out
}

func joinResults(parts ...[]json.RawMessage) []json.RawMessage {
	var out []json.RawMessage
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func urlsOf(t *testing.T, results []json.RawMessage) []string {
	t.Helper()
	var urls []string
	for _, raw := range results {
		var r struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal(raw, &r); err != nil {
			t.Fatal(err)
		}
		urls = append(urls, r.URL)
	}
	return urls
}

func TestFilterCatchAll(t *testing.T) {
	const host = "https://voltlaunchr.com"
	genuine := []json.RawMessage{
		ffufResult(host+"/admin", 200, 4821, 310),
		ffufResult(host+"/login", 302, 0, 1),
	}
	genuineURLs := []string{host + "/admin", host + "/login"}

	tests := []struct {
		name        string
		results     []json.RawMessage
		wantKept    []string // nil: compare only the count
		wantCount   int
		wantDropped []catchAll
	}{
		{
			name:        "real WAF flood keeps only genuine hits",
			results:     joinResults(wafFlood(host, 3871), genuine),
			wantKept:    genuineURLs,
			wantCount:   2,
			wantDropped: []catchAll{{host: host, fp: fingerprint{Status: 403, Length: 25103, Words: 1053}, count: 3871}},
		},
		{
			name:      "few identical responses are plausible and kept",
			results:   joinResults(identicalResults(host, catchAllMinCount-1, 301, 178), genuine),
			wantCount: catchAllMinCount - 1 + 2,
		},
		{
			name:      "frequent but not dominant fingerprint is kept",
			results:   joinResults(identicalResults(host, 30, 403, 199), variedResults(host, 30)),
			wantCount: 60,
		},
		{
			name:        "dominant fingerprint at the minimum count is dropped",
			results:     joinResults(identicalResults(host, catchAllMinCount, 403, 199), genuine),
			wantKept:    genuineURLs,
			wantCount:   2,
			wantDropped: []catchAll{{host: host, fp: fingerprint{Status: 403, Length: 199, Words: 7}, count: catchAllMinCount}},
		},
		{
			name: "two block pages under the share threshold are dropped by absolute count",
			results: joinResults(identicalResults(host, catchAllAbsoluteCount, 403, 500),
				identicalResults(host, catchAllAbsoluteCount, 200, 900), genuine),
			wantKept:  genuineURLs,
			wantCount: 2,
			wantDropped: []catchAll{
				{host: host, fp: fingerprint{Status: 200, Length: 900, Words: 7}, count: catchAllAbsoluteCount},
				{host: host, fp: fingerprint{Status: 403, Length: 500, Words: 7}, count: catchAllAbsoluteCount},
			},
		},
		{
			name:      "no results",
			wantCount: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kept, dropped := filterCatchAll(host, tt.results)
			if len(kept) != tt.wantCount {
				t.Fatalf("kept %d results, want %d", len(kept), tt.wantCount)
			}
			if tt.wantKept != nil {
				if got := urlsOf(t, kept); !reflect.DeepEqual(got, tt.wantKept) {
					t.Fatalf("kept = %v, want %v", got, tt.wantKept)
				}
			}
			if !reflect.DeepEqual(dropped, tt.wantDropped) {
				t.Fatalf("dropped = %+v, want %+v", dropped, tt.wantDropped)
			}
		})
	}
}

// docExecutor writes a fixed ffuf document per host (matched by substring
// of "-u") to each command's "-o" path.
type docExecutor struct {
	docs map[string][]json.RawMessage
}

func (e *docExecutor) Run(_ context.Context, command runner.Command) (*runner.CommandResult, error) {
	var outputPath, target string
	for i, arg := range command.Args {
		if arg == "-o" && i+1 < len(command.Args) {
			outputPath = command.Args[i+1]
		}
		if arg == "-u" && i+1 < len(command.Args) {
			target = command.Args[i+1]
		}
	}
	results := []json.RawMessage{}
	for host, docs := range e.docs {
		if strings.Contains(target, host) {
			results = append(results, docs...)
		}
	}
	data, _ := json.Marshal(map[string]any{"results": results})
	_ = os.WriteFile(outputPath, data, 0644)
	return &runner.CommandResult{Command: command}, nil
}

// TestRunDiscardsCatchAllFlood locks the fix for the real-world WAF flood:
// 3871 identical 403s must not reach discovered_paths (and therefore
// attacksurface and nuclei), genuine hits and other hosts must survive, the
// operator gets one warning, and the raw per-host file stays intact.
func TestRunDiscardsCatchAllFlood(t *testing.T) {
	run := testRun(t, t.TempDir())
	hosts := "https://voltlaunchr.com\nhttps://www.voltlaunchr.com\n"
	if err := os.WriteFile(run.Path("02_http", "httpx.txt"), []byte(hosts), 0644); err != nil {
		t.Fatal(err)
	}
	wordlist := filepath.Join(t.TempDir(), "words.txt")
	if err := os.WriteFile(wordlist, []byte("admin\n"), 0644); err != nil {
		t.Fatal(err)
	}
	runCtx := modules.NewRunContext("voltlaunchr.com", "web", false, run)
	if err := runCtx.AddArtifact("alive_urls", modules.Artifact{Name: "alive_urls", Type: "text", Path: "02_http/httpx.txt"}); err != nil {
		t.Fatal(err)
	}
	runCtx.Ffuf = modules.FfufOptions{Wordlist: wordlist}
	var (
		mu       sync.Mutex
		warnings []string
	)
	runCtx.SetWarningSink(func(msg string) {
		mu.Lock()
		warnings = append(warnings, msg)
		mu.Unlock()
	})

	flood := joinResults(wafFlood("https://voltlaunchr.com", 3871), []json.RawMessage{
		ffufResult("https://voltlaunchr.com/admin", 200, 4821, 310),
		ffufResult("https://voltlaunchr.com/login", 302, 0, 1),
	})
	executor := &docExecutor{docs: map[string][]json.RawMessage{
		"//voltlaunchr.com":     flood,
		"//www.voltlaunchr.com": {ffufResult("https://www.voltlaunchr.com/robots.txt", 200, 67, 4)},
	}}

	if _, err := New("ffuf").Run(context.Background(), runCtx, executor); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	data, err := os.ReadFile(run.Path("05_content", "ffuf.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc ffufDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"https://voltlaunchr.com/admin",
		"https://voltlaunchr.com/login",
		"https://www.voltlaunchr.com/robots.txt",
	}
	if got := urlsOf(t, doc.Results); !reflect.DeepEqual(got, want) {
		t.Fatalf("discovered paths = %v, want %v", got, want)
	}

	if len(warnings) != 1 {
		t.Fatalf("warnings = %q, want exactly one", warnings)
	}
	for _, part := range []string{"https://voltlaunchr.com ", "3871 identical responses", "status 403", "25103 bytes", "catch-all/WAF"} {
		if !strings.Contains(warnings[0], part) {
			t.Errorf("warning %q missing %q", warnings[0], part)
		}
	}

	raw, err := os.ReadFile(run.Path("05_content", "ffuf", "host-0001.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rawDoc ffufDocument
	if err := json.Unmarshal(raw, &rawDoc); err != nil {
		t.Fatal(err)
	}
	if len(rawDoc.Results) != 3873 {
		t.Fatalf("raw per-host file has %d results, want 3873 kept for audit", len(rawDoc.Results))
	}
}
