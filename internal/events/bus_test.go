package events

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/scope"
)

func newTestBus(t *testing.T, opts Options) (*Bus, string) {
	t.Helper()
	dir := t.TempDir()
	if opts.Scope == nil {
		s, err := scope.FromTarget("example.com", scope.ModeDomain, nil, []string{"admin.example.com"})
		if err != nil {
			t.Fatal(err)
		}
		opts.Scope = s
	}
	opts.MetaDir = dir
	b, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return b, dir
}

func readLines(t *testing.T, path string) []map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var out []map[string]any
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("bad jsonl line %q: %v", sc.Text(), err)
		}
		out = append(out, m)
	}
	return out
}

func TestNewRequiresScope(t *testing.T) {
	if _, err := New(Options{MetaDir: t.TempDir()}); err == nil {
		t.Fatal("expected error without scope")
	}
}

func TestDeterministicIDAndNormalization(t *testing.T) {
	cases := []struct {
		typ  Type
		a, b string
	}{
		{DNSName, "WWW.Example.com.", "www.example.com"},
		{LiveURL, "HTTPS://Example.com:443/a#frag", "https://example.com/a"},
		{OpenPort, " Example.com:80 ", "example.com:80"},
	}
	for _, c := range cases {
		ia, ib := MakeID(c.typ, Normalize(c.typ, c.a)), MakeID(c.typ, Normalize(c.typ, c.b))
		if ia != ib {
			t.Errorf("%s: %q and %q gave different IDs", c.typ, c.a, c.b)
		}
	}
	if MakeID(DNSName, "x.example.com") == MakeID(LiveURL, "x.example.com") {
		t.Error("type must be part of the ID")
	}
}

func TestDedup(t *testing.T) {
	b, dir := newTestBus(t, Options{})
	var got []string
	b.Subscribe(DNSName, func(e Event) { got = append(got, e.Value) })
	for _, v := range []string{"a.example.com", "A.example.com.", "b.example.com", "a.example.com"} {
		if _, err := b.Publish(Event{Type: DNSName, Value: v, Source: "t"}); err != nil {
			t.Fatal(err)
		}
	}
	b.Wait()
	if len(got) != 2 || got[0] != "a.example.com" || got[1] != "b.example.com" {
		t.Fatalf("got %v", got)
	}
	if s := b.Stats(); s.Delivered != 2 || s.Duplicates != 2 {
		t.Fatalf("stats %+v", s)
	}
	if n := len(readLines(t, filepath.Join(dir, "events.jsonl"))); n != 2 {
		t.Fatalf("persisted %d events, want 2", n)
	}
}

func TestSubscribeByType(t *testing.T) {
	b, _ := newTestBus(t, Options{})
	var dns, all int
	b.Subscribe(DNSName, func(Event) { dns++ })
	b.SubscribeAll(func(Event) { all++ })
	_, _ = b.Publish(Event{Type: DNSName, Value: "a.example.com"})
	_, _ = b.Publish(Event{Type: LiveURL, Value: "https://a.example.com/"})
	b.Wait()
	if dns != 1 || all != 2 {
		t.Fatalf("dns=%d all=%d", dns, all)
	}
}

func TestCycleTerminates(t *testing.T) {
	b, _ := newTestBus(t, Options{MaxDepth: 50})
	var n int
	// DNS_NAME -> LIVE_URL -> DNS_NAME (same value) -> ... would loop forever
	// without dedup.
	b.Subscribe(DNSName, func(e Event) {
		n++
		_, _ = b.Publish(Derive(e, LiveURL, "https://"+e.Value+"/", "dns"))
	})
	b.Subscribe(LiveURL, func(e Event) {
		n++
		_, _ = b.Publish(Derive(e, DNSName, "a.example.com", "http"))
	})
	_, _ = b.Publish(Event{Type: DNSName, Value: "a.example.com"})
	b.Wait()
	if n != 2 {
		t.Fatalf("handlers ran %d times, want 2", n)
	}
	if s := b.Stats(); s.Duplicates != 1 {
		t.Fatalf("stats %+v", s)
	}
}

func TestDepthLimit(t *testing.T) {
	b, _ := newTestBus(t, Options{MaxDepth: 2})
	var depths []int
	b.Subscribe(DNSName, func(e Event) {
		depths = append(depths, e.Depth)
		_, _ = b.Publish(Derive(e, DNSName, fmt.Sprintf("l%d.example.com", e.Depth+1), "t"))
	})
	_, _ = b.Publish(Event{Type: DNSName, Value: "l0.example.com"})
	b.Wait()
	if fmt.Sprint(depths) != "[0 1 2]" {
		t.Fatalf("depths %v", depths)
	}
	if s := b.Stats(); s.DepthExceeded != 1 {
		t.Fatalf("stats %+v", s)
	}
}

func TestUnknownParentRejected(t *testing.T) {
	b, _ := newTestBus(t, Options{})
	if _, err := b.Publish(Event{Type: DNSName, Value: "a.example.com", ParentID: "nope"}); err == nil {
		t.Fatal("expected error for unknown parent")
	}
}

func TestBudget(t *testing.T) {
	b, _ := newTestBus(t, Options{Budget: 3})
	var n int
	b.SubscribeAll(func(Event) { n++ })
	for i := 0; i < 10; i++ {
		_, _ = b.Publish(Event{Type: DNSName, Value: fmt.Sprintf("h%d.example.com", i)})
	}
	b.Wait()
	if n != 3 {
		t.Fatalf("delivered %d, want 3", n)
	}
	if s := b.Stats(); s.BudgetExhausted != 7 {
		t.Fatalf("stats %+v", s)
	}
}

func TestScopeDrop(t *testing.T) {
	b, dir := newTestBus(t, Options{})
	var got []string
	b.SubscribeAll(func(e Event) { got = append(got, e.Value) })

	cases := map[string]Disposition{
		"ok.example.com":    Delivered,
		"evil.org":          OutOfScope,
		"admin.example.com": OutOfScope, // excluded
	}
	for v, want := range cases {
		d, err := b.Publish(Event{Type: DNSName, Value: v, Source: "osint"})
		if err != nil || d != want {
			t.Errorf("%s: got %v,%v want %v", v, d, err, want)
		}
	}
	// Repeated rejection is counted but logged once.
	_, _ = b.Publish(Event{Type: DNSName, Value: "evil.org"})
	b.Wait()

	if len(got) != 1 || got[0] != "ok.example.com" {
		t.Fatalf("delivered %v", got)
	}
	for _, m := range readLines(t, filepath.Join(dir, "events.jsonl")) {
		if m["value"] == "evil.org" {
			t.Fatal("out-of-scope event persisted to events.jsonl")
		}
	}
	rej := readLines(t, filepath.Join(dir, "scope-rejections.jsonl"))
	if len(rej) != 2 {
		t.Fatalf("rejections %v", rej)
	}
	for _, k := range []string{"timestamp", "artifact", "path", "value", "reason"} {
		if _, ok := rej[0][k]; !ok {
			t.Errorf("rejection missing field %q", k)
		}
	}
	if rej[0]["artifact"] != "event:DNS_NAME" || rej[0]["reason"] != "outside configured scope" {
		t.Errorf("rejection %v", rej[0])
	}
}

func TestScopeRefAndFailClosed(t *testing.T) {
	b, _ := newTestBus(t, Options{})
	// A relative route has no host: rejected unless ScopeRef anchors it.
	d, _ := b.Publish(Event{Type: APIRoute, Value: "/api/v1/users"})
	if d != OutOfScope {
		t.Fatalf("bare route: %v", d)
	}
	d, _ = b.Publish(Event{Type: APIRoute, Value: "/api/v1/users", ScopeRef: "https://a.example.com"})
	if d != Delivered {
		t.Fatalf("anchored route: %v", d)
	}
	d, _ = b.Publish(Event{Type: APIRoute, Value: "/api/v1/other", ScopeRef: "https://evil.org"})
	if d != OutOfScope {
		t.Fatalf("foreign anchor: %v", d)
	}
}

func TestOSINTDiscoveryDoesNotWidenScope(t *testing.T) {
	b, _ := newTestBus(t, Options{})
	d, _ := b.Publish(Event{Type: DNSName, Value: "partner-cdn.net", Source: "osint"})
	if d != OutOfScope {
		t.Fatalf("got %v", d)
	}
	// Even as a child of an in-scope parent, scope still decides.
	_, _ = b.Publish(Event{Type: DNSName, Value: "a.example.com"})
	parent := Event{ID: MakeID(DNSName, "a.example.com")}
	d, _ = b.Publish(Derive(parent, DNSName, "partner-cdn.net", "osint"))
	if d != OutOfScope {
		t.Fatalf("child: got %v", d)
	}
}

func TestDeterministicOrdering(t *testing.T) {
	run := func() []string {
		b, dir := newTestBus(t, Options{})
		var order []string
		b.Subscribe(DNSName, func(e Event) {
			order = append(order, e.Value)
			if e.Depth == 0 {
				for _, c := range []string{"c1", "c2"} {
					_, _ = b.Publish(Derive(e, DNSName, c+"."+e.Value, "t"))
				}
			}
		})
		for _, v := range []string{"a.example.com", "b.example.com"} {
			_, _ = b.Publish(Event{Type: DNSName, Value: v})
		}
		b.Wait()
		for _, m := range readLines(t, filepath.Join(dir, "events.jsonl")) {
			order = append(order, "P:"+m["value"].(string))
		}
		return order
	}
	first := fmt.Sprint(run())
	for i := 0; i < 20; i++ {
		if got := fmt.Sprint(run()); got != first {
			t.Fatalf("non-deterministic:\n%s\n%s", first, got)
		}
	}
	// Each Publish drains synchronously; children of one event are
	// delivered FIFO before the next root is published.
	want := "[a.example.com c1.a.example.com c2.a.example.com b.example.com c1.b.example.com c2.b.example.com"
	if first[:len(want)] != want {
		t.Fatalf("order %s", first)
	}
}

func TestConcurrentPublish(t *testing.T) {
	b, dir := newTestBus(t, Options{Budget: 100000})
	var mu sync.Mutex
	seen := map[string]int{}
	b.Subscribe(DNSName, func(e Event) {
		mu.Lock()
		seen[e.Value]++
		mu.Unlock()
		// Handlers fan out concurrently-published children too.
		if e.Depth == 0 {
			_, _ = b.Publish(Derive(e, LiveURL, "https://"+e.Value+"/", "t"))
		}
	})
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				// 25 values shared across goroutines to force dedup races,
				// plus out-of-scope noise.
				_, _ = b.Publish(Event{Type: DNSName, Value: fmt.Sprintf("h%d.example.com", i%25)})
				_, _ = b.Publish(Event{Type: DNSName, Value: fmt.Sprintf("x%d.evil.org", i)})
			}
		}(g)
	}
	wg.Wait()
	b.Wait()
	if len(seen) != 25 {
		t.Fatalf("saw %d distinct, want 25", len(seen))
	}
	for v, n := range seen {
		if n != 1 {
			t.Errorf("%s delivered %d times", v, n)
		}
	}
	if n := len(readLines(t, filepath.Join(dir, "events.jsonl"))); n != 50 { // 25 DNS + 25 URL
		t.Fatalf("persisted %d, want 50", n)
	}
	if n := len(readLines(t, filepath.Join(dir, "scope-rejections.jsonl"))); n != 50 {
		t.Fatalf("rejections %d, want 50 (logged once each)", n)
	}
}

func TestEmitLines(t *testing.T) {
	b, dir := newTestBus(t, Options{})
	p := filepath.Join(t.TempDir(), "subdomains.txt")
	if err := os.WriteFile(p, []byte("a.example.com\n\nb.example.com\nevil.org\na.example.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	n, err := EmitLines(b, p, DNSName, "subfinder")
	if err != nil || n != 2 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if len(readLines(t, filepath.Join(dir, "events.jsonl"))) != 2 {
		t.Fatal("expected 2 persisted events")
	}
	if len(readLines(t, filepath.Join(dir, "scope-rejections.jsonl"))) != 1 {
		t.Fatal("expected 1 rejection")
	}
}
