package modules

import (
	"context"

	"github.com/MikeRoss27/scanforge/internal/runner"
)

type Result struct {
	Name        string
	Status      string
	OutputFiles map[string]string
	// Reason explains a non-completed Status the module chose itself, e.g.
	// why it skipped ("no WordPress detected"). Empty otherwise.
	Reason string
}

// SkipNotApplicable marks a successful result as skipped because the module
// had nothing to do (its input is empty or irrelevant for this target). The
// artifacts it published stay valid; only the status and reason change, so
// the console shows a single [SKIP] line instead of a warning plus [OK].
func SkipNotApplicable(res *Result, err error, reason string) (*Result, error) {
	if err != nil || res == nil {
		return res, err
	}
	res.Status = "skipped"
	res.Reason = reason
	return res, nil
}

// IsNotApplicable reports whether a result was skipped by the module itself
// (SkipNotApplicable) rather than by the orchestrator for a missing
// dependency.
func IsNotApplicable(res *Result) bool {
	return res != nil && res.Status == "skipped" && res.Reason != ""
}

type Module interface {
	Name() string
	Description() string
	Requires() []string
	Produces() []string
	Run(ctx context.Context, runCtx *RunContext, executor runner.Executor) (*Result, error)
}

// SoftRequires is an optional Module extension. Artifacts listed here should
// be produced before the module runs when their producer is part of the
// profile, but — unlike Requires — a missing producer is not a build error:
// the module reads those upstreams conditionally at runtime.
type SoftRequires interface {
	SoftRequires() []string
}
