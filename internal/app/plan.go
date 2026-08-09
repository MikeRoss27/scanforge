package app

import (
	"github.com/MikeRoss27/scanforge/internal/config"
	"github.com/MikeRoss27/scanforge/internal/orchestrator"
)

type PlanOptions struct {
	Target      string
	TargetsFile string
	Profile     string
	Scope       string
	ScopeMode   string
	ScopeAdd    []string
	Exclusions  []string
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

	var results []*PlanResult
	for _, target := range targets {
		result, err := a.planOne(cfg, target, profileName, opts)
		if err != nil {
			return nil, err
		}
		results = append(results, result)
	}
	return results, nil
}

func (a *App) planOne(cfg *config.Config, target, profileName string, opts PlanOptions) (*PlanResult, error) {
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
		Target:       target,
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
