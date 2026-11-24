package events

import (
	"path/filepath"
	"testing"
)

// A resumed run builds a new Bus over the same 00_meta: events are delivered
// again (subscribers still need them) but events.jsonl and
// scope-rejections.jsonl must not gain duplicate lines.
func TestResumedBusDeliversButDoesNotRewritePersistedLines(t *testing.T) {
	b1, dir := newTestBus(t, Options{})
	publish := func(b *Bus) (delivered []string) {
		b.Subscribe(DNSName, func(e Event) { delivered = append(delivered, e.Value) })
		for _, v := range []string{"a.example.com", "evil.org", "b.example.com"} {
			if _, err := b.Publish(Event{Type: DNSName, Value: v, Source: "t"}); err != nil {
				t.Fatal(err)
			}
		}
		b.Wait()
		return delivered
	}
	if got := publish(b1); len(got) != 2 {
		t.Fatalf("first pass delivered %v", got)
	}

	b2, err := New(Options{MetaDir: dir, Scope: b1.opts.Scope})
	if err != nil {
		t.Fatal(err)
	}
	if got := publish(b2); len(got) != 2 {
		t.Fatalf("resumed bus must still deliver events, got %v", got)
	}
	// A new value after the resume is persisted normally.
	if _, err := b2.Publish(Event{Type: DNSName, Value: "c.example.com", Source: "t"}); err != nil {
		t.Fatal(err)
	}
	if n := len(readLines(t, filepath.Join(dir, "events.jsonl"))); n != 3 {
		t.Fatalf("events.jsonl has %d lines, want 3 (a, b, c)", n)
	}
	if n := len(readLines(t, filepath.Join(dir, "scope-rejections.jsonl"))); n != 1 {
		t.Fatalf("scope-rejections.jsonl has %d lines, want 1", n)
	}
}
