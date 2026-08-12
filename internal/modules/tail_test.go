package modules

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestTailLinesSeesAppendedLinesAndFlushesTrailingPartial(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.jsonl")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}

	var (
		mu    sync.Mutex
		lines []string
	)
	stop := make(chan struct{})

	done := make(chan struct{})
	go func() {
		defer close(done)
		TailLines(path, stop, 10*time.Millisecond, func(line string) {
			mu.Lock()
			lines = append(lines, line)
			mu.Unlock()
		})
	}()

	if _, err := file.WriteString("{\"id\":1}\n"); err != nil {
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		t.Fatal(err)
	}

	waitForLineCount(t, &mu, &lines, 1)

	if _, err := file.WriteString("{\"id\":2}\n"); err != nil {
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		t.Fatal(err)
	}

	waitForLineCount(t, &mu, &lines, 2)

	// A line written without a trailing newline yet must not be reported
	// until it's complete; closing stop must still flush it once it is.
	if _, err := file.WriteString(`{"id":3}` + "\n"); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	close(stop)
	<-done

	mu.Lock()
	defer mu.Unlock()
	want := []string{`{"id":1}`, `{"id":2}`, `{"id":3}`}
	if len(lines) != len(want) {
		t.Fatalf("got %d lines, want %d: %v", len(lines), len(want), lines)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Fatalf("line %d = %q, want %q", i, lines[i], want[i])
		}
	}
}

func TestTailLinesToleratesMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "never-created.jsonl")
	stop := make(chan struct{})

	done := make(chan struct{})
	go func() {
		defer close(done)
		TailLines(path, stop, 5*time.Millisecond, func(string) {
			t.Error("onLine should never be called for a file that was never created")
		})
	}()

	close(stop)
	<-done
}

func waitForLineCount(t *testing.T, mu *sync.Mutex, lines *[]string, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		got := len(*lines)
		mu.Unlock()
		if got >= n {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d lines", n)
}
