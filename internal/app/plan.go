package app

import (
	"fmt"

	"github.com/MikeRoss27/scanforge/internal/config"
	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/orchestrator"
	"github.com/MikeRoss27/scanforge/internal/workflows"
)

type PlanOptions struct {
	Target      string
	TargetsFile string
	Profile     string
	// Workflow is a YAML workflow path replacing the profile.
	Workflow   string
	Scope      string
	ScopeMode  string
	ScopeAdd   []string
	Exclusions []string
	// WP adds the WordPress engagement chain to the resolved profile.
	WP bool
}

type PlanStep struct {
	Wave        int
	Name        string
	Binary      string
	Risk        string
	Description string
	Requires    []string
	Produces    []string
}

type PlanResult struct {
	Target       string
	Profile      string
	Scope        string
	ScopeSource  string
	ScopeMode    string
	ScopeNote    string
	ScopeEntries []string
	// ProbeHint is the host:port the user named in their target. It is
	// probed by httpx in addition to the default ports; it is not part of
	// the scope, which only ever covers the host.
	ProbeHint string
	Steps     []PlanStep
}

// Plan validates the profile DAG and scope for every target and returns one
// PlanResult per target (multi-target support via --targets).
func (a *App) Plan(opts PlanOptions) ([]*PlanResult, error) {
	targets, err := expandTargets(opts.Target, opts.TargetsFile)
	if err != nil {
		return nil, err
	}
	cfg, err := a.loadConfig()
	if err != nil {
		return nil, err
	}
	profileName := opts.Profile
	if profileName == "" {
		profileName = cfg.DefaultProfile
	}

	var compiled *workflows.Compiled
	if opts.Workflow != "" {
		if err := checkWorkflowExclusive(opts.Profile, opts.WP); err != nil {
			return nil, err
		}
		if compiled, err = loadWorkflow(cfg, opts.Workflow); err != nil {
			return nil, fmt.Errorf("workflow: %w", err)
		}
		profileName = workflowProfilePrefix + compiled.Name
	}

	var results []*PlanResult
	for _, target := range targets {
		result, err := a.planOne(cfg, target, profileName, opts, compiled)
		if err != nil {
			return nil, err
		}
		results = append(results, result)
	}
	return results, nil
}

func (a *App) planOne(cfg *config.Config, target, profileName string, opts PlanOptions, compiled *workflows.Compiled) (*PlanResult, error) {
	effective, err := resolveScope(
		cfg,
		target,
		opts.Scope,
		opts.ScopeMode,
		opts.ScopeAdd,
		opts.Exclusions,
	)
	if err != nil {
		return nil, err
	}

	var names []string
	if compiled != nil {
		names = compiled.Modules
	} else {
		names, err = cfg.ProfileModules(profileName)
		if err != nil {
			return nil, err
		}
		names = applyWordPress(names, opts.WP, false)
	}
	selected, err := buildRegistry(cfg).Resolve(names)
	if err != nil {
		return nil, err
	}
	rawSteps, err := orchestrator.BuildPlan(selected)
	if err != nil {
		return nil, err
	}
	result := &PlanResult{
		Target:       target,
		Profile:      profileName,
		Scope:        effective.proposal.Input,
		ScopeSource:  effective.proposal.Source,
		ScopeMode:    effective.proposal.Mode,
		ScopeNote:    effective.proposal.Note,
		ScopeEntries: effective.proposal.Entries,
	}
	if hint, ok := modules.TargetProbe(target); ok {
		result.ProbeHint = hint
	}
	for _, step := range rawSteps {
		result.Steps = append(result.Steps, PlanStep{
			Wave: step.Wave, Name: step.Name, Binary: cfg.ToolPath(step.Name),
			Risk: moduleRisk(step.Name), Description: step.Description,
			Requires: step.Requires, Produces: step.Produces,
		})
	}
	return result, nil
}

func moduleRisk(name string) string {
	switch name {
	case "subfinder", "gau", "techcve", "attacksurface":
		return "passive"
	case "dbdetect":
		return "active-low"
	case "dbenum":
		return "active-high"
	case "dnsbrute":
		return "active-low"
	case "dnsx", "httpx", "tlsx", "whatweb", "wafw00f", "jssecrets", "jsverify":
		return "active-low"
	case "screenshot", "httpcheck":
		return "active-low"
	case "katana", "naabu":
		return "active"
	case "wpdetect", "wpplugins", "wpthemes", "wpusers", "wpexposure", "wpxmlrpc", "wpcve":
		return "active-low"
	case "wpbrute":
		return "active-high"
	case "nmap", "ffuf", "nuclei":
		return "active-high"
	default:
		return "unknown"
	}
}
