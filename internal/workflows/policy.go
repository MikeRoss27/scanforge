package workflows

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
)

// Registry returns a registry where every module of the workflow is wrapped
// with its step policy (when / timeout / retries / on_error). The wrapped
// modules keep the exact Name, Requires, Produces and SoftRequires of the
// originals, so the DAG, the scope filter in RunContext.AddArtifact and the
// orchestrator are untouched.
func (c *Compiled) Registry(base *modules.Registry) (*modules.Registry, error) {
	reg := modules.NewRegistry()
	for _, name := range c.Modules {
		m, ok := base.Get(name)
		if !ok {
			return nil, fmt.Errorf("module %q not found in registry", name)
		}
		reg.Register(&policyModule{inner: m, policy: c.Policies[name], backoff: defaultBackoff})
	}
	return reg, nil
}

func defaultBackoff(attempt int) time.Duration { return time.Duration(attempt) * 2 * time.Second }

type policyModule struct {
	inner   modules.Module
	policy  Policy
	backoff func(attempt int) time.Duration
}

func (p *policyModule) Name() string        { return p.inner.Name() }
func (p *policyModule) Description() string { return p.inner.Description() }
func (p *policyModule) Requires() []string  { return p.inner.Requires() }
func (p *policyModule) Produces() []string  { return p.inner.Produces() }
func (p *policyModule) SoftRequires() []string {
	if sr, ok := p.inner.(modules.SoftRequires); ok {
		return sr.SoftRequires()
	}
	return nil
}

func (p *policyModule) Run(ctx context.Context, rc *modules.RunContext, ex runner.Executor) (*modules.Result, error) {
	name := p.inner.Name()
	if w := p.policy.When; w != nil && !rc.DryRun {
		ok, why := evalWhen(rc, w)
		if !ok {
			return &modules.Result{Name: name, Status: "skipped", Reason: why}, nil
		}
	}

	var res *modules.Result
	var err error
	attempts := p.policy.Retries + 1
	for attempt := 1; attempt <= attempts; attempt++ {
		res, err = p.attempt(ctx, rc, ex)
		if err == nil || ctx.Err() != nil || errors.Is(err, context.Canceled) {
			break
		}
		if attempt < attempts {
			rc.EmitWarning(fmt.Sprintf("step %q (%s) failed (attempt %d/%d): %v; retrying", p.policy.StepID, name, attempt, attempts, err))
			select {
			case <-ctx.Done():
			case <-time.After(p.backoff(attempt)):
			}
			if ctx.Err() != nil {
				break
			}
		}
	}
	if err == nil {
		return res, nil
	}
	if ctx.Err() != nil || errors.Is(err, context.Canceled) {
		return res, err // user abort is never softened by on_error
	}

	switch p.policy.OnError {
	case OnErrorContinue:
		rc.EmitWarning(fmt.Sprintf("step %q (%s) failed, continuing (on_error=continue): %v", p.policy.StepID, name, err))
		out := &modules.Result{Name: name, Status: "failed"}
		if res != nil {
			out.OutputFiles = res.OutputFiles
		}
		return out, nil
	case OnErrorSkip:
		return &modules.Result{Name: name, Status: "skipped", Reason: "failed, skipped (on_error=skip): " + err.Error()}, nil
	}
	return res, err
}

func (p *policyModule) attempt(ctx context.Context, rc *modules.RunContext, ex runner.Executor) (*modules.Result, error) {
	if p.policy.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.policy.Timeout)
		defer cancel()
	}
	res, err := p.inner.Run(ctx, rc, ex)
	if err != nil && p.policy.Timeout > 0 && errors.Is(err, context.DeadlineExceeded) {
		err = fmt.Errorf("step %q timed out after %s: %w", p.policy.StepID, p.policy.Timeout, err)
	}
	return res, err
}

// evalWhen evaluates the closed set of declarative conditions.
func evalWhen(rc *modules.RunContext, w *When) (bool, string) {
	name := w.Artifact()
	art, ok := rc.GetArtifact(name)
	if !ok {
		return false, fmt.Sprintf("condition not met: artifact %q not produced", name)
	}
	if !w.NonEmpty() {
		return true, ""
	}
	if !artifactNonEmpty(art.Path) {
		return false, fmt.Sprintf("condition not met: artifact %q is empty", name)
	}
	return true, ""
}

func artifactNonEmpty(path string) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	if info.IsDir() {
		entries, err := os.ReadDir(path)
		return err == nil && len(entries) > 0
	}
	if info.Size() == 0 {
		return false
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	buf, _ := io.ReadAll(io.LimitReader(f, 1<<20))
	return len(strings.TrimSpace(string(buf))) > 0
}
