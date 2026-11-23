// Package benchmark runs ScanForge's full pipeline against known,
// intentionally-vulnerable lab targets (Google's Firing Range, Acunetix's
// testphp.vulnweb.com, OWASP Juice Shop's public demo, a locally self-hosted
// DVWA) and scores the resulting report against documented expectations.
//
// This is a maintainer/CI regression-detection tool, not part of an
// authorized client engagement workflow: it is wired into the CLI under
// "scanforge benchmark" (see internal/cli/benchmark.go) specifically so both
// a human contributor and an AI agent can sanity-check a change against
// real-world-shaped targets with a clean, machine-parseable result.
package benchmark

import (
	"embed"
	"fmt"
	"sort"
	"time"

	"gopkg.in/yaml.v3"
)

//go:embed corpus/*.yaml
var corpusFS embed.FS

// CategoryExpectation is one vulnerability category a lab is expected to
// surface, matched against a report's Vulnerability.Tags, Title and
// TemplateID (case-insensitive substring match on any Keyword).
type CategoryExpectation struct {
	Name     string   `yaml:"name" json:"name"`
	Keywords []string `yaml:"keywords" json:"keywords"`
	MinCount int      `yaml:"min_count" json:"min_count"`
}

// Lab describes one benchmark target: where to scan, how, and what the
// resulting report should contain.
type Lab struct {
	Name        string `yaml:"name" json:"name"`
	Description string `yaml:"description" json:"description"`
	Target      string `yaml:"target" json:"target"`
	// ScopeMode is "exact" or "domain" — passed straight through to
	// app.RunOptions.ScopeMode.
	ScopeMode string `yaml:"scope_mode" json:"scope_mode"`
	Profile   string `yaml:"profile" json:"profile"`
	// Timeout serializes as plain nanoseconds in JSON (encoding/json's
	// default for time.Duration) — stable and unambiguous for a machine
	// reader, if not pretty.
	Timeout time.Duration `yaml:"timeout" json:"timeout"`
	// Strict gates the benchmark's overall pass/fail on ExpectedCategories.
	// Non-strict labs still compute and report category results, but only
	// a failed/crashed pipeline run fails the benchmark for them — see
	// score.go. Only a lab with a precisely known, pinned vulnerability set
	// (today: dvwa, run against a fixed Docker image) should be strict.
	Strict bool `yaml:"strict" json:"strict"`
	// Setup, when non-empty, is printed instead of running the lab when its
	// target is unreachable (e.g. DVWA needs a manual docker run first).
	Setup string `yaml:"setup" json:"setup,omitempty"`
	// Notes is informational context always shown (shared public infra,
	// known test fragility, a self-hosted alternative, ...).
	Notes                string                `yaml:"notes" json:"notes,omitempty"`
	ExpectedTechnologies []string              `yaml:"expected_technologies" json:"expected_technologies,omitempty"`
	ExpectedCategories   []CategoryExpectation `yaml:"expected_categories" json:"expected_categories,omitempty"`
}

// Labs returns every bundled lab, sorted by name for a stable, predictable
// order in --help, "list" and "--all".
func Labs() ([]Lab, error) {
	entries, err := corpusFS.ReadDir("corpus")
	if err != nil {
		return nil, fmt.Errorf("failed to read bundled benchmark corpus: %w", err)
	}
	labs := make([]Lab, 0, len(entries))
	for _, entry := range entries {
		data, err := corpusFS.ReadFile("corpus/" + entry.Name())
		if err != nil {
			return nil, fmt.Errorf("failed to read bundled lab %q: %w", entry.Name(), err)
		}
		var lab Lab
		if err := yaml.Unmarshal(data, &lab); err != nil {
			return nil, fmt.Errorf("failed to parse bundled lab %q: %w", entry.Name(), err)
		}
		if lab.Name == "" {
			return nil, fmt.Errorf("bundled lab %q has no name", entry.Name())
		}
		if lab.Target == "" {
			return nil, fmt.Errorf("lab %q has no target", lab.Name)
		}
		if lab.Profile == "" {
			return nil, fmt.Errorf("lab %q has no profile", lab.Name)
		}
		labs = append(labs, lab)
	}
	sort.Slice(labs, func(i, j int) bool { return labs[i].Name < labs[j].Name })
	return labs, nil
}

// LabByName returns the bundled lab with the given name, or an error naming
// every available lab when it doesn't exist.
func LabByName(name string) (Lab, error) {
	labs, err := Labs()
	if err != nil {
		return Lab{}, err
	}
	var names []string
	for _, lab := range labs {
		names = append(names, lab.Name)
		if lab.Name == name {
			return lab, nil
		}
	}
	return Lab{}, fmt.Errorf("unknown benchmark lab %q (available: %v)", name, names)
}
