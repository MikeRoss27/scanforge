package app

import (
	"fmt"

	"github.com/MikeRoss27/scanforge/internal/orchestrator"
)

type PlanOptions struct {
	Target     string
	Profile    string
	Scope      string
	ScopeMode  string
	ScopeAdd   []string
	Exclusions []string
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
	Steps        []PlanStep
}

func (a *App) Plan(opts PlanOptions) (*PlanResult, error) {
	cfg, err := a.loadConfig()
	if err != nil {
		return nil, err
	}
	if opts.Target == "" {
		return nil, fmt.Errorf("target is required")
	}
	profileName := opts.Profile
	if profileName == "" {
		profileName = cfg.DefaultProfile
	}
	effective, err := resolveScope(
		cfg,
		opts.Target,
		opts.Scope,
		opts.ScopeMode,
		opts.ScopeAdd,
		opts.Exclusions,
	)
	if err != nil {
		return nil, err
	}

	names, err := cfg.ProfileModules(profileName)
	if err != nil {
		return nil, err
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
		Target:       opts.Target,
		Profile:      profileName,
		Scope:        effective.proposal.Input,
		ScopeSource:  effective.proposal.Source,
		ScopeMode:    effective.proposal.Mode,
		ScopeNote:    effective.proposal.Note,
		ScopeEntries: effective.proposal.Entries,
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
	case "subfinder", "gau":
		return "passive"
	case "dnsx", "httpx", "tlsx", "whatweb", "wafw00f", "jssecrets", "jsverify":
		return "active-low"
	case "katana", "naabu":
		return "active"
	case "nmap", "ffuf", "nuclei":
		return "active-high"
	default:
		return "unknown"
	}
}
