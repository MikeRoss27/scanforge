package active

import (
	"fmt"

	"github.com/MikeRoss27/scanforge/internal/app"
)

// PlanRequest is the read-only plan input.
type PlanRequest struct {
	Target  string
	Profile string
	WP      bool
}

// PlanStepView is the JSON form of one planned module.
type PlanStepView struct {
	Wave        int      `json:"wave"`
	Module      string   `json:"module"`
	Risk        string   `json:"risk"`
	Description string   `json:"description,omitempty"`
	Requires    []string `json:"requires,omitempty"`
	Produces    []string `json:"produces,omitempty"`
}

// PlanView is the JSON form of a plan. It carries no credentials.
type PlanView struct {
	Target       string         `json:"target"`
	Profile      string         `json:"profile"`
	ScopeSource  string         `json:"scope_source"`
	ScopeMode    string         `json:"scope_mode"`
	ScopeEntries []string       `json:"scope_entries"`
	ScopeNote    string         `json:"scope_note,omitempty"`
	Steps        []PlanStepView `json:"steps"`
}

// Plan wraps the existing plan logic. It never creates a run directory and is
// always available. When the server has an explicit scope file the plan is
// validated against it (strict semantics).
func (c *Controller) Plan(req PlanRequest) (*PlanView, error) {
	if err := ValidTarget(req.Target); err != nil {
		return nil, err
	}
	if c.planner == nil {
		return nil, fmt.Errorf("planner unavailable")
	}
	if req.Profile != "" && !profileRE.MatchString(req.Profile) {
		return nil, fmt.Errorf("%w: profile %q", ErrInvalid, req.Profile)
	}
	opts := app.PlanOptions{Target: req.Target, Profile: req.Profile, WP: req.WP}
	if c.cfg.ScopeFile != "" {
		opts.Scope = c.cfg.ScopeFile
	}
	results, err := c.planner(opts)
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("no plan produced")
	}
	r := results[0]
	v := &PlanView{
		Target: r.Target, Profile: r.Profile, ScopeSource: r.ScopeSource, ScopeMode: r.ScopeMode,
		ScopeEntries: r.ScopeEntries, ScopeNote: r.ScopeNote, Steps: []PlanStepView{},
	}
	for _, s := range r.Steps {
		v.Steps = append(v.Steps, PlanStepView{Wave: s.Wave, Module: s.Name, Risk: s.Risk, Description: s.Description, Requires: s.Requires, Produces: s.Produces})
	}
	return v, nil
}
