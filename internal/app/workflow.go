package app

import (
	"fmt"

	"github.com/MikeRoss27/scanforge/internal/config"
	"github.com/MikeRoss27/scanforge/internal/workflows"
)

// workflowProfilePrefix names the pseudo-profile recorded in the manifest
// and console for a workflow run.
const workflowProfilePrefix = "workflow:"

// loadWorkflow parses and validates a workflow file against the real module
// registry. The result compiles to the same ordered module list a profile
// yields; scope enforcement is untouched.
func loadWorkflow(cfg *config.Config, path string) (*workflows.Compiled, error) {
	wf, err := workflows.Load(path)
	if err != nil {
		return nil, err
	}
	return wf.Validate(buildRegistry(cfg))
}

// ValidateWorkflow validates a workflow file without executing anything.
func (a *App) ValidateWorkflow(path string) (*workflows.Compiled, error) {
	cfg, err := a.loadConfig()
	if err != nil {
		return nil, err
	}
	return loadWorkflow(cfg, path)
}

// checkWorkflowExclusive rejects mixing a workflow with profile selection:
// the workflow is the profile.
func checkWorkflowExclusive(profile string, wp bool) error {
	if profile != "" {
		return fmt.Errorf("--workflow cannot be combined with --profile/--preset")
	}
	if wp {
		return fmt.Errorf("--workflow cannot be combined with --wp (list the wp* modules in the workflow)")
	}
	return nil
}

// mergeWorkflowOverrides applies workflow step params only where the operator
// did not set the matching CLI flag: explicit flags always win.
func mergeWorkflowOverrides(opts *RunOptions, o workflows.Overrides) {
	n, wn := &opts.Nuclei, o.Nuclei
	setStr := func(dst *string, v string) {
		if *dst == "" {
			*dst = v
		}
	}
	setStr(&n.Severity, wn.Severity)
	setStr(&n.ExcludeSeverity, wn.ExcludeSeverity)
	setStr(&n.Tags, wn.Tags)
	setStr(&n.ExcludeTags, wn.ExcludeTags)
	setStr(&n.TemplatesDir, wn.TemplatesDir)
	if n.RateLimit == 0 {
		n.RateLimit = wn.RateLimit
	}
	if n.Timeout == 0 {
		n.Timeout = wn.Timeout
	}
	n.UpdateTemplates = n.UpdateTemplates || wn.UpdateTemplates
	n.Headless = n.Headless || wn.Headless
	n.IncludeCustomTemplates = n.IncludeCustomTemplates || wn.IncludeCustomTemplates
	n.FullScan = n.FullScan || wn.FullScan

	setStr(&opts.Ffuf.Wordlist, o.Ffuf.Wordlist)
	setStr(&opts.Ffuf.FilterCodes, o.Ffuf.FilterCodes)
	if opts.NmapConcurrency == 0 {
		opts.NmapConcurrency = o.NmapConcurrency
	}
	// The CLI default for --wp-detection-mode is "passive"; only an empty
	// value is treated as unset, so a workflow value applies when no flag
	// default has been injected.
	if opts.WordPress.DetectionMode == "" || opts.WordPress.DetectionMode == "passive" {
		if o.WordPress.DetectionMode != "" {
			opts.WordPress.DetectionMode = o.WordPress.DetectionMode
		}
	}
	setStr(&opts.WordPress.Wordlist, o.WordPress.Wordlist)
}
