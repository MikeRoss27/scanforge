// Package modules defines the scanner integration contract (Module, artifacts,
// run context) and the registry used to resolve them.
package modules

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	scanScope "github.com/MikeRoss27/scanforge/internal/scope"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

type Artifact struct {
	Name string
	Type string
	Path string
}

type RunContext struct {
	Target         string
	Profile        string
	DryRun         bool
	Run            *storage.Run
	Scope          *scanScope.Scope
	Artifacts      map[string]Artifact
	artifactErrors map[string]error
	mu             sync.RWMutex

	// Proxy is an optional HTTP/SOCKS proxy (e.g. a Caido or Burp listener
	// such as http://127.0.0.1:8080) that HTTP-capable modules route their
	// traffic through, so findings can be intercepted and triaged manually.
	Proxy string
	// Headers are raw "Name: Value" entries applied to every outgoing HTTP
	// request by modules that support it (e.g. session cookies or auth
	// tokens for authenticated scanning).
	Headers []string
	// Nuclei carries nuclei-specific tuning that has no equivalent in other
	// modules (severity/tag filtering, rate limiting, custom templates).
	Nuclei NucleiOptions
	// Ffuf carries ffuf-specific tuning (wordlist selection, status-code
	// filtering).
	Ffuf FfufOptions
	// NmapConcurrency bounds how many nmap processes run at once. <= 0 means
	// the module picks its own default.
	NmapConcurrency int
}

// FfufOptions configures the ffuf module's fuzzing inputs.
type FfufOptions struct {
	// Wordlist is the directory/file wordlist used for path fuzzing. Empty
	// means the module default (/usr/share/wordlists/dirb/common.txt).
	Wordlist string
	// FilterCodes are comma-separated HTTP status codes to filter out
	// (ffuf -fc), e.g. "404,500".
	FilterCodes string
}

// NucleiOptions configures the nuclei module's template selection and pacing.
type NucleiOptions struct {
	Severity        string
	ExcludeSeverity string
	Tags            string
	ExcludeTags     string
	RateLimit       int
	TemplatesDir    string
	UpdateTemplates bool
	// Headless enables headless-mode templates (renders pages in a browser).
	Headless bool
	// IncludeCustomTemplates appends the repository's bundled custom template
	// directory to the nuclei scan.
	IncludeCustomTemplates bool
	// CustomTemplatesDir overrides the bundled custom template directory path.
	CustomTemplatesDir string
}

func NewRunContext(target, profile string, dryRun bool, run *storage.Run, scopes ...*scanScope.Scope) *RunContext {
	var allowedScope *scanScope.Scope
	if len(scopes) > 0 {
		allowedScope = scopes[0]
	}
	return &RunContext{
		Target:         target,
		Profile:        profile,
		DryRun:         dryRun,
		Run:            run,
		Scope:          allowedScope,
		Artifacts:      make(map[string]Artifact),
		artifactErrors: make(map[string]error),
	}
}

// AddArtifact publishes a module output for downstream consumers. Text artifacts
// are filtered in place first, making this the central scope boundary for all
// line-oriented host, URL, IP, and host:port lists.
func (c *RunContext) AddArtifact(name string, artifact Artifact) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.filterArtifact(name, artifact); err != nil {
		c.artifactErrors[name] = err
		return err
	}
	c.Artifacts[name] = artifact
	delete(c.artifactErrors, name)
	return nil
}

func (c *RunContext) GetArtifact(name string) (Artifact, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	art, ok := c.Artifacts[name]
	return art, ok
}

// IsInScope reports whether value is within the configured scope. A missing
// scope (tests, some dry runs) allows everything.
func (c *RunContext) IsInScope(value string) bool {
	if c.Scope == nil {
		return true
	}
	return c.Scope.IsAllowed(value)
}

func (c *RunContext) MustArtifact(name string) (Artifact, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if art, ok := c.Artifacts[name]; ok {
		return art, nil
	}
	if err, ok := c.artifactErrors[name]; ok {
		return Artifact{}, fmt.Errorf("artifact %q failed scope validation: %w", name, err)
	}
	available := []string{}
	for k := range c.Artifacts {
		available = append(available, k)
	}
	return Artifact{}, fmt.Errorf("required artifact %q not found (available: %s)", name, strings.Join(available, ", "))
}

type scopeRejection struct {
	Timestamp string `json:"timestamp"`
	Artifact  string `json:"artifact"`
	Path      string `json:"path"`
	Value     string `json:"value"`
	Reason    string `json:"reason"`
}

var scopedTextArtifacts = map[string]struct{}{
	"subdomains":          {},
	"resolved_hosts":      {},
	"alive_urls":          {},
	"crawled_urls":        {},
	"open_ports":          {},
	"historical_urls":     {},
	"attack_surface_urls": {},
}

func (c *RunContext) filterArtifact(name string, artifact Artifact) error {
	_, requiresScopeFilter := scopedTextArtifacts[name]
	if c.Scope == nil || c.Run == nil || c.DryRun || artifact.Type != "text" || !requiresScopeFilter {
		return nil
	}

	path := c.Run.Path(artifact.Path)
	input, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open artifact %q: %w", path, err)
	}
	defer func() { _ = input.Close() }()

	tmp, err := os.CreateTemp(filepath.Dir(path), ".scope-filter-*")
	if err != nil {
		return fmt.Errorf("create filtered artifact: %w", err)
	}
	tmpPath := tmp.Name()
	keepTemp := false
	defer func() {
		_ = tmp.Close()
		if !keepTemp {
			_ = os.Remove(tmpPath)
		}
	}()

	scanner := bufio.NewScanner(input)
	writer := bufio.NewWriter(tmp)
	var rejected []scopeRejection
	for scanner.Scan() {
		value := strings.TrimSpace(scanner.Text())
		if value == "" {
			continue
		}
		if !c.Scope.IsAllowed(value) {
			rejected = append(rejected, scopeRejection{
				Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
				Artifact:  name,
				Path:      artifact.Path,
				Value:     value,
				Reason:    "outside configured scope",
			})
			continue
		}
		if _, err := writer.WriteString(value + "\n"); err != nil {
			return fmt.Errorf("write filtered artifact: %w", err)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read artifact %q: %w", path, err)
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("flush filtered artifact: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close filtered artifact: %w", err)
	}
	if err := os.Chmod(tmpPath, 0644); err != nil {
		return fmt.Errorf("set filtered artifact permissions: %w", err)
	}
	// Record rejections before replacing the artifact: if the log write
	// fails, the artifact is left unpublished and the original file intact,
	// keeping the state consistent for downstream consumers.
	if len(rejected) > 0 {
		if err := c.appendScopeRejections(rejected); err != nil {
			return err
		}
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace artifact with filtered output: %w", err)
	}
	keepTemp = true

	return nil
}

func (c *RunContext) appendScopeRejections(rejections []scopeRejection) error {
	path := filepath.Join(c.Run.MetaDir, "scope-rejections.jsonl")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("open scope rejection log: %w", err)
	}
	defer func() { _ = file.Close() }()

	encoder := json.NewEncoder(file)
	for _, rejection := range rejections {
		if err := encoder.Encode(rejection); err != nil {
			return fmt.Errorf("write scope rejection log: %w", err)
		}
	}
	if c.Run.Manifest.Outputs == nil {
		c.Run.Manifest.Outputs = make(map[string]string)
	}
	c.Run.Manifest.Outputs["scope_rejections"] = "00_meta/scope-rejections.jsonl"
	return nil
}
