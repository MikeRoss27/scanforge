// Package workflows loads, validates and compiles declarative YAML workflows
// into the same module selection the profile mechanism produces, so the DAG
// orchestrator and the scope enforcement stay the single execution path.
//
// A workflow can only select registered modules and tune them; it can never
// run arbitrary commands, and its `when` conditions are a closed declarative
// form (artifact present / non-empty), not code.
package workflows

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	// MaxFileSize bounds the workflow file read from disk.
	MaxFileSize = 256 * 1024
	// MaxSteps bounds the number of steps in one workflow.
	MaxSteps = 64
	// SupportedVersion is the only workflow schema version understood.
	SupportedVersion = 1

	MinTimeout = time.Second
	MaxTimeout = 24 * time.Hour
	MaxRetries = 5

	OnErrorFail     = "fail"
	OnErrorContinue = "continue"
	OnErrorSkip     = "skip"
)

var (
	idPattern       = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)
	namePattern     = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)
	artifactPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

	// forbiddenKeys are rejected anywhere in the document: workflows must
	// never be able to carry command execution.
	forbiddenKeys = map[string]bool{
		"run": true, "exec": true, "shell": true, "command": true, "cmd": true,
		"script": true, "sh": true, "bash": true, "eval": true, "args": true,
	}
)

// Workflow is the parsed (not yet validated against the registry) document.
type Workflow struct {
	Name        string `yaml:"name"`
	Version     int    `yaml:"version"`
	Description string `yaml:"description"`
	Steps       []Step `yaml:"steps"`
}

// Step is one module invocation with its execution policy.
type Step struct {
	ID      string         `yaml:"id"`
	Module  string         `yaml:"module"`
	Needs   []string       `yaml:"needs"`
	Timeout string         `yaml:"timeout"`
	Retries int            `yaml:"retries"`
	OnError string         `yaml:"on_error"`
	When    *When          `yaml:"when"`
	Params  map[string]any `yaml:"params"`

	timeout time.Duration
}

// When is the closed set of safe conditions. Exactly one field is set.
type When struct {
	ArtifactPresent  string `yaml:"artifact_present"`
	ArtifactNonEmpty string `yaml:"artifact_nonempty"`
}

// Artifact returns the artifact name the condition refers to.
func (w *When) Artifact() string {
	if w.ArtifactPresent != "" {
		return w.ArtifactPresent
	}
	return w.ArtifactNonEmpty
}

// NonEmpty reports whether the condition requires non-empty content.
func (w *When) NonEmpty() bool { return w.ArtifactNonEmpty != "" }

// Load reads and parses a workflow file.
func Load(path string) (*Workflow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open workflow: %w", err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, MaxFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read workflow: %w", err)
	}
	w, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return w, nil
}

// Parse decodes and structurally validates a workflow document. It does not
// need the module registry; see Validate for the semantic checks.
func Parse(data []byte) (*Workflow, error) {
	if len(data) > MaxFileSize {
		return nil, fmt.Errorf("workflow file too large (max %d bytes)", MaxFileSize)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errors.New("workflow is empty")
	}

	var root yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&root); err != nil {
		return nil, fmt.Errorf("invalid YAML: %w", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("multiple YAML documents are not allowed")
	}
	if err := scanNode(&root); err != nil {
		return nil, err
	}

	var w Workflow
	strict := yaml.NewDecoder(bytes.NewReader(data))
	strict.KnownFields(true)
	if err := strict.Decode(&w); err != nil {
		return nil, fmt.Errorf("invalid workflow: %w", err)
	}
	if err := w.check(); err != nil {
		return nil, err
	}
	return &w, nil
}

// scanNode rejects aliases/anchors/merge tricks and any key that would imply
// command execution, at any depth.
func scanNode(n *yaml.Node) error {
	if n.Kind == yaml.AliasNode || n.Anchor != "" {
		return fmt.Errorf("line %d: YAML anchors and aliases are not allowed", n.Line)
	}
	if n.Tag == "!!merge" {
		return fmt.Errorf("line %d: YAML merge keys are not allowed", n.Line)
	}
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if forbiddenKeys[strings.ToLower(k.Value)] {
				return fmt.Errorf("line %d: key %q is forbidden: workflows cannot execute commands, they can only select registered modules", k.Line, k.Value)
			}
		}
	}
	for _, c := range n.Content {
		if err := scanNode(c); err != nil {
			return err
		}
	}
	return nil
}

// check performs the registry-independent structural validation.
func (w *Workflow) check() error {
	if !namePattern.MatchString(w.Name) {
		return fmt.Errorf("name %q is invalid (letters, digits, '.', '_', '-', max 64, must start alphanumeric)", w.Name)
	}
	if w.Version != SupportedVersion {
		return fmt.Errorf("unsupported version %d (expected %d)", w.Version, SupportedVersion)
	}
	if len(w.Steps) == 0 {
		return errors.New("workflow has no steps")
	}
	if len(w.Steps) > MaxSteps {
		return fmt.Errorf("too many steps (%d, max %d)", len(w.Steps), MaxSteps)
	}
	seen := make(map[string]bool, len(w.Steps))
	for i := range w.Steps {
		s := &w.Steps[i]
		if !idPattern.MatchString(s.ID) {
			return fmt.Errorf("step #%d: id %q is invalid (letters, digits, '_', '-', max 64)", i+1, s.ID)
		}
		if seen[s.ID] {
			return fmt.Errorf("duplicate step id %q", s.ID)
		}
		seen[s.ID] = true
		if s.Module == "" {
			return fmt.Errorf("step %q: module is required", s.ID)
		}
		if s.Timeout != "" {
			d, err := time.ParseDuration(s.Timeout)
			if err != nil {
				return fmt.Errorf("step %q: bad timeout %q: %v", s.ID, s.Timeout, err)
			}
			if d < MinTimeout || d > MaxTimeout {
				return fmt.Errorf("step %q: timeout %s out of range [%s, %s]", s.ID, d, MinTimeout, MaxTimeout)
			}
			s.timeout = d
		}
		if s.Retries < 0 || s.Retries > MaxRetries {
			return fmt.Errorf("step %q: retries %d out of range [0, %d]", s.ID, s.Retries, MaxRetries)
		}
		switch s.OnError {
		case "":
			s.OnError = OnErrorFail
		case OnErrorFail, OnErrorContinue, OnErrorSkip:
		default:
			return fmt.Errorf("step %q: on_error %q must be fail, continue or skip", s.ID, s.OnError)
		}
		if s.When != nil {
			if err := s.When.check(); err != nil {
				return fmt.Errorf("step %q: %w", s.ID, err)
			}
		}
	}
	return nil
}

func (w *When) check() error {
	set := 0
	for _, v := range []string{w.ArtifactPresent, w.ArtifactNonEmpty} {
		if v != "" {
			set++
			if !artifactPattern.MatchString(v) {
				return fmt.Errorf("when: invalid artifact name %q", v)
			}
		}
	}
	if set != 1 {
		return errors.New("when: set exactly one of artifact_present or artifact_nonempty")
	}
	return nil
}
