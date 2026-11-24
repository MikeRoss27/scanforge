package modules

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// InputFocus narrows the URL inputs of the expensive active modules in an
// incremental run. Keep must be safe for concurrent use. It can only remove
// lines from an already scope-filtered artifact, never add any.
type InputFocus interface {
	// Keep reports whether the URL still has to be scanned.
	Keep(value string) bool
	// Digest identifies the focus state for the checkpoint input hash.
	Digest() string
}

// focusableArtifacts are the line-oriented URL artifacts a focus may narrow.
var focusableArtifacts = map[string]struct{}{
	"alive_urls":          {},
	"attack_surface_urls": {},
	"crawled_urls":        {},
}

// FocusStats describes the outcome of FocusedInput.
type FocusStats struct {
	// Active is true when a focus narrowed the input.
	Active bool
	Kept   int
	Total  int
}

// Empty reports whether a focus left nothing to scan.
func (s FocusStats) Empty() bool { return s.Active && s.Kept == 0 }

// SkipReason is the skip reason of a module whose focused input is empty.
func (s FocusStats) SkipReason() string {
	return fmt.Sprintf("incremental: no new or changed URLs (%d unchanged)", s.Total)
}

// SetInputFocus installs the incremental focus. Must be called before
// modules start running.
func (c *RunContext) SetInputFocus(f InputFocus) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.focus = f
}

// InputFocus returns the installed focus, or nil.
func (c *RunContext) InputFocus() InputFocus {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.focus
}

// FocusedInput is MustArtifact for modules that only need to look at new or
// changed URLs in an incremental run. Without a focus (the default) it
// returns the artifact untouched. With one, it writes a sibling
// "<name>.incremental.<ext>" file holding the lines that are both inside the
// effective scope (re-checked here) and kept by the focus, and returns it.
func (c *RunContext) FocusedInput(name string) (Artifact, FocusStats, error) {
	art, err := c.MustArtifact(name)
	if err != nil {
		return art, FocusStats{}, err
	}
	focus := c.InputFocus()
	if _, ok := focusableArtifacts[name]; !ok || focus == nil || c.Run == nil || c.DryRun || art.Type != "text" {
		return art, FocusStats{}, nil
	}
	src := c.Run.Path(art.Path)
	in, err := os.Open(src)
	if err != nil {
		return art, FocusStats{}, fmt.Errorf("open artifact %q: %w", src, err)
	}
	defer func() { _ = in.Close() }()

	ext := filepath.Ext(art.Path)
	rel := strings.TrimSuffix(art.Path, ext) + ".incremental" + ext
	tmp, err := os.CreateTemp(filepath.Dir(src), ".incremental-*")
	if err != nil {
		return art, FocusStats{}, fmt.Errorf("create focused input: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	stats := FocusStats{Active: true}
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	w := bufio.NewWriter(tmp)
	for scanner.Scan() {
		value := strings.TrimSpace(scanner.Text())
		if value == "" {
			continue
		}
		stats.Total++
		if !c.IsInScope(value) || !focus.Keep(value) {
			continue
		}
		stats.Kept++
		if _, err := w.WriteString(value + "\n"); err != nil {
			_ = tmp.Close()
			return art, FocusStats{}, fmt.Errorf("write focused input: %w", err)
		}
	}
	if err := scanner.Err(); err != nil {
		_ = tmp.Close()
		return art, FocusStats{}, fmt.Errorf("read artifact %q: %w", src, err)
	}
	if err := w.Flush(); err != nil {
		_ = tmp.Close()
		return art, FocusStats{}, err
	}
	if err := tmp.Close(); err != nil {
		return art, FocusStats{}, err
	}
	if err := os.Rename(tmpPath, c.Run.Path(rel)); err != nil {
		return art, FocusStats{}, fmt.Errorf("publish focused input: %w", err)
	}
	art.Path = rel
	return art, stats, nil
}
