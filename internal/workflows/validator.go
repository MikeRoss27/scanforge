package workflows

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/orchestrator"
)

// Catalog is the module lookup the validator needs; *modules.Registry
// satisfies it.
type Catalog interface {
	Get(name string) (modules.Module, bool)
}

// deniedModules cannot be used from a workflow file: wpbrute is opt-in only
// and needs explicit CLI flags (--wp-bruteforce, --wp-passwords).
var deniedModules = map[string]string{
	"wpbrute": "brute force is opt-in via --wp-bruteforce and cannot be enabled from a workflow",
}

// Policy is the execution policy of one compiled step.
type Policy struct {
	StepID  string
	Timeout time.Duration
	Retries int
	OnError string
	When    *When
}

// Overrides carries the per-step params mapped onto the existing module
// configuration. Zero values mean "not set by the workflow".
type Overrides struct {
	Nuclei          modules.NucleiOptions
	Ffuf            modules.FfufOptions
	NmapConcurrency int
	WordPress       modules.WordPressOptions
}

// Compiled is a validated workflow reduced to what the profile mechanism
// produces (an ordered module list) plus the per-module policies.
type Compiled struct {
	Name      string
	Modules   []string
	Policies  map[string]Policy
	Overrides Overrides
	Waves     []orchestrator.PlanStep
}

// Validate checks the workflow against the module catalog and compiles it.
// It rejects unknown modules, duplicate modules, unknown/duplicate/cyclic
// needs, needs that contradict the modules' Requires()/Produces() artifacts,
// invalid params and unreachable `when` conditions.
func (w *Workflow) Validate(cat Catalog) (*Compiled, error) {
	if err := w.check(); err != nil {
		return nil, err
	}

	byID := make(map[string]*Step, len(w.Steps))
	mods := make(map[string]modules.Module, len(w.Steps))
	usedModule := make(map[string]string, len(w.Steps))
	producers := make(map[string]string)
	var soft = make(map[string][]string)

	for i := range w.Steps {
		s := &w.Steps[i]
		byID[s.ID] = s
		if reason, denied := deniedModules[s.Module]; denied {
			return nil, fmt.Errorf("step %q: module %q is not allowed in workflows: %s", s.ID, s.Module, reason)
		}
		m, ok := cat.Get(s.Module)
		if !ok {
			return nil, fmt.Errorf("step %q: unknown module %q", s.ID, s.Module)
		}
		if prev, dup := usedModule[s.Module]; dup {
			return nil, fmt.Errorf("step %q: module %q is already used by step %q (one step per module)", s.ID, s.Module, prev)
		}
		usedModule[s.Module] = s.ID
		mods[s.ID] = m
		for _, a := range m.Produces() {
			if p, dup := producers[a]; dup {
				return nil, fmt.Errorf("step %q: artifact %q is already produced by step %q", s.ID, a, p)
			}
			producers[a] = s.ID
		}
		if sr, ok := m.(modules.SoftRequires); ok {
			soft[s.ID] = sr.SoftRequires()
		}
	}

	// needs: known, not self, not duplicated, acyclic.
	for _, s := range w.Steps {
		seen := map[string]bool{}
		for _, n := range s.Needs {
			switch {
			case n == s.ID:
				return nil, fmt.Errorf("step %q: needs itself", s.ID)
			case byID[n] == nil:
				return nil, fmt.Errorf("step %q: needs unknown step %q", s.ID, n)
			case seen[n]:
				return nil, fmt.Errorf("step %q: duplicate need %q", s.ID, n)
			}
			seen[n] = true
		}
	}
	if cyc := findNeedsCycle(w.Steps); cyc != "" {
		return nil, fmt.Errorf("dependency cycle in needs: %s", cyc)
	}

	needsClosure := closure(w.Steps, func(s *Step) []string { return s.Needs })
	artifactEdges := func(s *Step) []string {
		var out []string
		for _, a := range append(append([]string{}, mods[s.ID].Requires()...), soft[s.ID]...) {
			if p, ok := producers[a]; ok {
				out = append(out, p)
			}
		}
		return out
	}
	artifactClosure := closure(w.Steps, artifactEdges)

	for i := range w.Steps {
		s := &w.Steps[i]
		// Every hard-required artifact needs a producer step that the step
		// declares (directly or transitively) in needs.
		for _, a := range mods[s.ID].Requires() {
			p, ok := producers[a]
			if !ok {
				return nil, fmt.Errorf("step %q: module %q requires artifact %q but no step produces it; add a step with a module producing it", s.ID, s.Module, a)
			}
			if !needsClosure[s.ID][p] {
				return nil, fmt.Errorf("step %q: module %q requires artifact %q produced by step %q, which is missing from needs (needs must follow the module artifacts)", s.ID, s.Module, a, p)
			}
		}
		// Every declared need must be justified by the artifact graph:
		// ordering is derived from artifacts, so an unrelated need would be
		// silently ignored by the scheduler.
		for _, n := range s.Needs {
			if !artifactClosure[s.ID][n] {
				return nil, fmt.Errorf("step %q: needs %q but module %q does not consume any artifact produced (directly or transitively) by module %q; ordering is artifact-driven", s.ID, n, s.Module, byID[n].Module)
			}
		}
		if s.When != nil {
			a := s.When.Artifact()
			p, ok := producers[a]
			if !ok {
				return nil, fmt.Errorf("step %q: when refers to artifact %q that no step produces", s.ID, a)
			}
			if p != s.ID && !needsClosure[s.ID][p] {
				return nil, fmt.Errorf("step %q: when refers to artifact %q produced by step %q, which is missing from needs", s.ID, a, p)
			}
			if p == s.ID {
				return nil, fmt.Errorf("step %q: when refers to an artifact produced by the step itself", s.ID)
			}
		}
	}

	out := &Compiled{Name: w.Name, Policies: make(map[string]Policy, len(w.Steps))}
	var selected []modules.Module
	for i := range w.Steps {
		s := &w.Steps[i]
		out.Modules = append(out.Modules, s.Module)
		selected = append(selected, mods[s.ID])
		out.Policies[s.Module] = Policy{StepID: s.ID, Timeout: s.timeout, Retries: s.Retries, OnError: s.OnError, When: s.When}
		if err := applyParams(&out.Overrides, s); err != nil {
			return nil, err
		}
	}

	// Final authority: the real DAG builder (cycles through artifacts,
	// producer conflicts) and planner, exactly as for a profile.
	plan, err := orchestrator.BuildPlan(selected)
	if err != nil {
		return nil, fmt.Errorf("workflow DAG: %w", err)
	}
	out.Waves = plan
	return out, nil
}

// closure computes, per step id, the set of step ids reachable through edges.
func closure(steps []Step, edges func(*Step) []string) map[string]map[string]bool {
	byID := make(map[string]*Step, len(steps))
	for i := range steps {
		byID[steps[i].ID] = &steps[i]
	}
	res := make(map[string]map[string]bool, len(steps))
	for i := range steps {
		set := map[string]bool{}
		stack := append([]string{}, edges(&steps[i])...)
		for len(stack) > 0 {
			n := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if set[n] || byID[n] == nil {
				continue
			}
			set[n] = true
			stack = append(stack, edges(byID[n])...)
		}
		res[steps[i].ID] = set
	}
	return res
}

func findNeedsCycle(steps []Step) string {
	byID := make(map[string]*Step, len(steps))
	for i := range steps {
		byID[steps[i].ID] = &steps[i]
	}
	state := map[string]int{}
	var path []string
	var visit func(id string) string
	visit = func(id string) string {
		switch state[id] {
		case 1:
			idx := 0
			for i, p := range path {
				if p == id {
					idx = i
					break
				}
			}
			return strings.Join(append(append([]string{}, path[idx:]...), id), " -> ")
		case 2:
			return ""
		}
		state[id] = 1
		path = append(path, id)
		for _, n := range byID[id].Needs {
			if byID[n] == nil {
				continue
			}
			if c := visit(n); c != "" {
				return c
			}
		}
		path = path[:len(path)-1]
		state[id] = 2
		return ""
	}
	for i := range steps {
		if c := visit(steps[i].ID); c != "" {
			return c
		}
	}
	return ""
}

// paramSpec describes one accepted param and how it maps to module config.
type paramSpec struct {
	kind string // string | int | bool | duration | enum:a,b
	min  int
	max  int
	set  func(*Overrides, any)
}

var paramSchemas = map[string]map[string]paramSpec{
	"nuclei": {
		"severity":         {kind: "string", set: func(o *Overrides, v any) { o.Nuclei.Severity = v.(string) }},
		"exclude_severity": {kind: "string", set: func(o *Overrides, v any) { o.Nuclei.ExcludeSeverity = v.(string) }},
		"tags":             {kind: "string", set: func(o *Overrides, v any) { o.Nuclei.Tags = v.(string) }},
		"exclude_tags":     {kind: "string", set: func(o *Overrides, v any) { o.Nuclei.ExcludeTags = v.(string) }},
		"rate_limit":       {kind: "int", min: 1, max: 10000, set: func(o *Overrides, v any) { o.Nuclei.RateLimit = v.(int) }},
		"templates":        {kind: "string", set: func(o *Overrides, v any) { o.Nuclei.TemplatesDir = v.(string) }},
		"update_templates": {kind: "bool", set: func(o *Overrides, v any) { o.Nuclei.UpdateTemplates = v.(bool) }},
		"headless":         {kind: "bool", set: func(o *Overrides, v any) { o.Nuclei.Headless = v.(bool) }},
		"include_custom":   {kind: "bool", set: func(o *Overrides, v any) { o.Nuclei.IncludeCustomTemplates = v.(bool) }},
		"full_scan":        {kind: "bool", set: func(o *Overrides, v any) { o.Nuclei.FullScan = v.(bool) }},
		"scan_timeout":     {kind: "duration", set: func(o *Overrides, v any) { o.Nuclei.Timeout = v.(time.Duration) }},
	},
	"ffuf": {
		"wordlist":     {kind: "string", set: func(o *Overrides, v any) { o.Ffuf.Wordlist = v.(string) }},
		"filter_codes": {kind: "string", set: func(o *Overrides, v any) { o.Ffuf.FilterCodes = v.(string) }},
	},
	"nmap": {
		"concurrency": {kind: "int", min: 1, max: 64, set: func(o *Overrides, v any) { o.NmapConcurrency = v.(int) }},
	},
}

func init() {
	wp := map[string]paramSpec{
		"detection_mode": {kind: "enum:passive,mixed,aggressive", set: func(o *Overrides, v any) { o.WordPress.DetectionMode = v.(string) }},
		"wordlist":       {kind: "string", set: func(o *Overrides, v any) { o.WordPress.Wordlist = v.(string) }},
	}
	for _, m := range []string{"wpplugins", "wpthemes"} {
		paramSchemas[m] = wp
	}
}

const maxParamString = 512

func applyParams(o *Overrides, s *Step) error {
	if len(s.Params) == 0 {
		return nil
	}
	schema, ok := paramSchemas[s.Module]
	if !ok {
		return fmt.Errorf("step %q: module %q accepts no params", s.ID, s.Module)
	}
	keys := make([]string, 0, len(s.Params))
	for k := range s.Params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		spec, ok := schema[k]
		if !ok {
			return fmt.Errorf("step %q: unknown param %q for module %q (allowed: %s)", s.ID, k, s.Module, allowed(schema))
		}
		v, err := coerce(spec, s.Params[k])
		if err != nil {
			return fmt.Errorf("step %q: param %q: %w", s.ID, k, err)
		}
		var tmp Overrides
		spec.set(&tmp, v)
		if (tmp.WordPress.DetectionMode != "" && o.WordPress.DetectionMode != "" && tmp.WordPress.DetectionMode != o.WordPress.DetectionMode) ||
			(tmp.WordPress.Wordlist != "" && o.WordPress.Wordlist != "" && tmp.WordPress.Wordlist != o.WordPress.Wordlist) {
			return fmt.Errorf("step %q: param %q conflicts with another step (WordPress options are shared by all wp* modules)", s.ID, k)
		}
		spec.set(o, v)
	}
	return nil
}

func allowed(schema map[string]paramSpec) string {
	names := make([]string, 0, len(schema))
	for k := range schema {
		names = append(names, k)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

func coerce(spec paramSpec, raw any) (any, error) {
	switch {
	case spec.kind == "string" || strings.HasPrefix(spec.kind, "enum:"):
		str, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("expected a string, got %T", raw)
		}
		if len(str) > maxParamString {
			return nil, fmt.Errorf("string too long (max %d)", maxParamString)
		}
		for _, r := range str {
			if r < 0x20 || r == 0x7f {
				return nil, fmt.Errorf("control characters are not allowed")
			}
		}
		if after, ok := strings.CutPrefix(spec.kind, "enum:"); ok {
			for _, c := range strings.Split(after, ",") {
				if str == c {
					return str, nil
				}
			}
			return nil, fmt.Errorf("must be one of %s", after)
		}
		return str, nil
	case spec.kind == "int":
		n, ok := raw.(int)
		if !ok {
			return nil, fmt.Errorf("expected an integer, got %T", raw)
		}
		if n < spec.min || n > spec.max {
			return nil, fmt.Errorf("%d out of range [%d, %d]", n, spec.min, spec.max)
		}
		return n, nil
	case spec.kind == "bool":
		b, ok := raw.(bool)
		if !ok {
			return nil, fmt.Errorf("expected a boolean, got %T", raw)
		}
		return b, nil
	case spec.kind == "duration":
		str, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("expected a duration string such as \"45m\", got %T", raw)
		}
		d, err := time.ParseDuration(str)
		if err != nil {
			return nil, err
		}
		if d < MinTimeout || d > MaxTimeout {
			return nil, fmt.Errorf("duration %s out of range [%s, %s]", d, MinTimeout, MaxTimeout)
		}
		return d, nil
	}
	return nil, fmt.Errorf("unsupported param kind %q", spec.kind)
}
