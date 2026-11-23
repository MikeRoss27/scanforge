package app

import (
	"path/filepath"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/config"
	"github.com/MikeRoss27/scanforge/internal/workflows"
)

// TestExampleWorkflowsAreValid keeps the shipped examples in sync with the
// real module registry (names, artifacts, params).
func TestExampleWorkflowsAreValid(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "workflows", "*.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no example workflows found: %v", err)
	}
	cfg := config.Default()
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			c, err := loadWorkflow(cfg, f)
			if err != nil {
				t.Fatal(err)
			}
			if len(c.Waves) != len(c.Modules) {
				t.Fatalf("plan has %d steps for %d modules", len(c.Waves), len(c.Modules))
			}
		})
	}
}

func TestMergeWorkflowOverridesCLIWins(t *testing.T) {
	opts := RunOptions{NmapConcurrency: 8}
	opts.Nuclei.Severity = "critical"
	var o workflows.Overrides
	o.NmapConcurrency = 2
	o.Nuclei.Severity = "low"
	o.Nuclei.RateLimit = 10
	mergeWorkflowOverrides(&opts, o)
	if opts.NmapConcurrency != 8 || opts.Nuclei.Severity != "critical" || opts.Nuclei.RateLimit != 10 {
		t.Fatalf("opts = %+v", opts)
	}
}

func TestWorkflowExclusiveWithProfile(t *testing.T) {
	if err := checkWorkflowExclusive("web", false); err == nil {
		t.Fatal("expected error")
	}
	if err := checkWorkflowExclusive("", true); err == nil {
		t.Fatal("expected error")
	}
	if err := checkWorkflowExclusive("", false); err != nil {
		t.Fatal(err)
	}
}
