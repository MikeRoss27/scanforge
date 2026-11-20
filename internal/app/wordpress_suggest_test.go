package app

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

const wpSuggestHomepage = `<html><head>
<meta name="generator" content="WordPress 6.4.2" />
</head><body>plain homepage</body></html>`

type fakeWPPrompter struct {
	tty      bool
	accepted bool
	calls    int
	target   string
}

func (p *fakeWPPrompter) IsTTY() bool { return p.tty }

func (p *fakeWPPrompter) Confirm(target, _ string) (bool, error) {
	p.calls++
	p.target = target
	return p.accepted, nil
}

func wordPressFixtureServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(wpSuggestHomepage))
	}))
	t.Cleanup(server.Close)
	return server
}

func TestMaybeSuggestWordPressSkipsWhenWPAlreadySet(t *testing.T) {
	application := New("")
	prompter := &fakeWPPrompter{tty: true, accepted: true}
	application.WPPrompter = prompter

	names := []string{"httpx"}
	got := application.maybeSuggestWordPress(RunOptions{Target: "http://example.invalid", WP: true}, names)
	if !reflect.DeepEqual(got, names) {
		t.Fatalf("got %v, want unchanged %v", got, names)
	}
	if prompter.calls != 0 {
		t.Fatalf("prompter should never be consulted when --wp is already set, got %d calls", prompter.calls)
	}
}

func TestMaybeSuggestWordPressSkipsOnDryRun(t *testing.T) {
	application := New("")
	prompter := &fakeWPPrompter{tty: true, accepted: true}
	application.WPPrompter = prompter

	names := []string{"httpx"}
	got := application.maybeSuggestWordPress(RunOptions{Target: "http://example.invalid", DryRun: true}, names)
	if !reflect.DeepEqual(got, names) {
		t.Fatalf("got %v, want unchanged %v", got, names)
	}
	if prompter.calls != 0 {
		t.Fatalf("a dry run must never probe the network, got %d prompt calls", prompter.calls)
	}
}

func TestMaybeSuggestWordPressAcceptedAddsChain(t *testing.T) {
	server := wordPressFixtureServer(t)
	application := New("")
	prompter := &fakeWPPrompter{tty: true, accepted: true}
	application.WPPrompter = prompter

	names := []string{"httpx"}
	got := application.maybeSuggestWordPress(RunOptions{Target: server.URL}, names)
	if prompter.calls != 1 {
		t.Fatalf("expected exactly one prompt, got %d", prompter.calls)
	}
	if prompter.target != server.URL {
		t.Fatalf("prompt target = %q, want %q", prompter.target, server.URL)
	}
	want := applyWordPress(names, true, false)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want the WordPress chain appended: %v", got, want)
	}
}

func TestMaybeSuggestWordPressDeclinedLeavesUnchanged(t *testing.T) {
	server := wordPressFixtureServer(t)
	application := New("")
	prompter := &fakeWPPrompter{tty: true, accepted: false}
	application.WPPrompter = prompter

	names := []string{"httpx"}
	got := application.maybeSuggestWordPress(RunOptions{Target: server.URL}, names)
	if prompter.calls != 1 {
		t.Fatalf("expected exactly one prompt, got %d", prompter.calls)
	}
	if !reflect.DeepEqual(got, names) {
		t.Fatalf("declining must leave the module list unchanged, got %v", got)
	}
}

func TestMaybeSuggestWordPressNonInteractiveNeverBlocksOrChanges(t *testing.T) {
	server := wordPressFixtureServer(t)
	application := New("")
	prompter := &fakeWPPrompter{tty: false}
	application.WPPrompter = prompter

	names := []string{"httpx"}
	got := application.maybeSuggestWordPress(RunOptions{Target: server.URL}, names)
	if prompter.calls != 0 {
		t.Fatalf("a non-TTY run must never be prompted, got %d calls", prompter.calls)
	}
	if !reflect.DeepEqual(got, names) {
		t.Fatalf("a non-interactive run must not silently change the module list, got %v", got)
	}
}

func TestMaybeSuggestWordPressNonWordPressSiteNeverPrompts(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><body>just a plain site</body></html>"))
	}))
	defer server.Close()

	application := New("")
	prompter := &fakeWPPrompter{tty: true, accepted: true}
	application.WPPrompter = prompter

	names := []string{"httpx"}
	got := application.maybeSuggestWordPress(RunOptions{Target: server.URL}, names)
	if prompter.calls != 0 {
		t.Fatalf("a non-WordPress site must never trigger the prompt, got %d calls", prompter.calls)
	}
	if !reflect.DeepEqual(got, names) {
		t.Fatalf("got %v, want unchanged %v", got, names)
	}
}
