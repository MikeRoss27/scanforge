package discovery

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/modules"
)

func httpxArgs(x *fakeExec) string {
	for _, c := range x.cmds {
		if c.Name == "httpx" {
			return strings.Join(c.Args, " ")
		}
	}
	return ""
}

func TestFollowUpHTTPXProbesDAGWebPorts(t *testing.T) {
	x := &fakeExec{}
	rc, eng, root := newEnv(t, "example.com", Options{}, x)
	publish(t, rc, root, "alive_urls", "02/alive.txt", "text",
		"http://www.example.com:8080\nhttps://www.example.com\nhttp://www.example.com:8080/x\nhttps://www.example.com:8443\n", true)
	publish(t, rc, root, "js_secrets", "06/js.jsonl", "jsonl", jsLine("https://www.example.com/a.js", "internal-host", "late.example.com"), false)
	if err := eng.Process(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := httpxArgs(x); !strings.Contains(got, "-ports 80,443,8080,8443") {
		t.Fatalf("httpx must probe the web ports of the DAG, got: %s", got)
	}
}

func TestFollowUpHTTPXWithoutAliveURLsKeepsDefaultPorts(t *testing.T) {
	x := &fakeExec{}
	rc, eng, root := newEnv(t, "example.com", Options{}, x)
	publish(t, rc, root, "js_secrets", "06/js.jsonl", "jsonl", jsLine("https://www.example.com/a.js", "internal-host", "late.example.com"), false)
	if err := eng.Process(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := httpxArgs(x); got == "" || strings.Contains(got, "-ports") {
		t.Fatalf("no alive_urls: httpx must keep its defaults, got: %q", got)
	}
}

func TestNoticesAnnounceFollowUpPasses(t *testing.T) {
	x := &fakeExec{crawl: map[string][]string{
		"http://late.example.com": {"http://c.example.com/"},
	}}
	var mu sync.Mutex
	var notes []string
	opts := Options{MaxDepth: 2, Notice: func(m string) {
		mu.Lock()
		notes = append(notes, m)
		mu.Unlock()
	}}
	rc, eng, root := newEnv(t, "example.com", opts, x)
	publish(t, rc, root, "js_secrets", "06/js.jsonl", "jsonl", jsLine("https://www.example.com/a.js", "internal-host", "late.example.com"), false)
	if err := eng.Process(context.Background()); err != nil {
		t.Fatal(err)
	}
	all := strings.Join(notes, "\n")
	for _, want := range []string{"resolve+probe late.example.com", "crawl http://late.example.com", "resolve+probe c.example.com", "done, 3 jobs", "1 past depth"} {
		if !strings.Contains(all, want) {
			t.Fatalf("notices lack %q:\n%s", want, all)
		}
	}
	if st := eng.Stats(); st.DroppedDepth != 1 {
		t.Fatalf("DroppedDepth = %d, want 1 (live URL of c at depth 3)", st.DroppedDepth)
	}
}

func TestBudgetExhaustionIsNotAFailureNorOverAnnounced(t *testing.T) {
	var notes []string
	x := &fakeExec{}
	rc, eng, root := newEnv(t, "example.com", Options{Budget: 2, Notice: func(m string) { notes = append(notes, m) }}, x)
	var lines string
	for _, h := range []string{"a", "b", "c"} {
		lines += jsLine("https://www.example.com/a.js", "internal-host", h+".example.com")
	}
	publish(t, rc, root, "js_secrets", "06/js.jsonl", "jsonl", lines, false)
	if err := eng.Process(context.Background()); err != nil {
		t.Fatal(err)
	}
	st := eng.Stats()
	if st.Failed != 0 || st.Commands != 2 || st.SkippedBudget == 0 {
		t.Fatalf("stats = %+v", st)
	}
	for _, n := range notes {
		if strings.Contains(n, "[3/2]") {
			t.Fatalf("announced a pass beyond the budget: %q", n)
		}
	}
}

// A resumed run rebuilds the engine over the same run directory: completed
// follow-ups must be replayed from their outputs (no command, same events),
// and new jobs must not overwrite earlier outputs.
func TestResumeReusesCompletedFollowUps(t *testing.T) {
	crawl := map[string][]string{"http://late.example.com": {"http://c.example.com/"}}
	x1 := &fakeExec{crawl: crawl}
	rc1, eng1, root := newEnv(t, "example.com", Options{MaxDepth: 3}, x1)
	publish(t, rc1, root, "js_secrets", "06/js.jsonl", "jsonl", jsLine("https://www.example.com/a.js", "internal-host", "late.example.com"), false)
	if err := eng1.Process(context.Background()); err != nil {
		t.Fatal(err)
	}
	first := len(x1.cmds)
	if first == 0 {
		t.Fatal("first pass ran nothing")
	}

	// Same directory, fresh context/bus/engine, as `scanforge resume` does.
	x2 := &fakeExec{crawl: crawl}
	var notes []string
	run := rc1.Run
	rc2 := modules.NewRunContext("example.com", "recon", false, run, rc1.Scope)
	if err := rc2.EnableEventsWith(modules.EventsOptions{MaxDepth: 3, Extended: true}); err != nil {
		t.Fatal(err)
	}
	eng2, err := New(rc2, x2, Options{MaxDepth: 3, Notice: func(m string) { notes = append(notes, m) }})
	if err != nil {
		t.Fatal(err)
	}
	publish(t, rc2, root, "js_secrets", "06/js.jsonl", "jsonl", jsLine("https://www.example.com/a.js", "internal-host", "late.example.com"), false)
	if err := eng2.Process(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(x2.cmds) != 0 {
		t.Fatalf("resume re-ran %d commands: %v", len(x2.cmds), x2.cmds)
	}
	if st := eng2.Stats(); st.Commands != 0 || st.Jobs != eng1.Stats().Jobs {
		t.Fatalf("resumed stats = %+v, first = %+v", st, eng1.Stats())
	}
	all := strings.Join(notes, "\n")
	// The whole chain is replayed, including the name found by the crawl.
	for _, want := range []string{"reuse resolve+probe late.example.com", "reuse crawl http://late.example.com", "reuse resolve+probe c.example.com"} {
		if !strings.Contains(all, want) {
			t.Fatalf("resume notices lack %q:\n%s", want, all)
		}
	}
	seen := map[string]bool{}
	for _, l := range strings.Split(strings.TrimSpace(readFile(t, filepath.Join(root, "00_meta", "events.jsonl"))), "\n") {
		if seen[l] {
			t.Fatalf("duplicate events.jsonl line after resume: %s", l)
		}
		seen[l] = true
	}
}

func TestNoticeWhenNothingToFollowUp(t *testing.T) {
	var notes []string
	_, eng, _ := newEnv(t, "example.com", Options{Notice: func(m string) { notes = append(notes, m) }}, &fakeExec{})
	if err := eng.Process(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "no new in-scope discovery") {
		t.Fatalf("notes = %v", notes)
	}
}
