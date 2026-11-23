// Package scheduler provides a global, in-memory resource scheduler that
// decorates a runner.Executor: it bounds concurrent commands, rate-limits
// command launches (token bucket), enforces a per-run budget and applies a
// uniform command timeout. Modules are unaware of it.
//
// Granularity: the scheduler sees commands, not the HTTP requests a tool
// issues internally. Each launched command costs Config.Cost (default 1)
// against both the token bucket and the budget. Per-request throttling of
// tools is done by capping the rate flags a module already passes (see
// capRateFlags), never by adding flags a module did not build.
package scheduler

import (
	"context"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/MikeRoss27/scanforge/internal/runner"
)

// ErrBudgetExhausted is returned when the run's request budget is spent.
var ErrBudgetExhausted = errors.New("global request budget exhausted")

// Config holds the global limits. A zero value disables the matching limit.
type Config struct {
	// Concurrency is the maximum number of commands running at once.
	Concurrency int
	// RPS is the global launch rate (tokens/second) and the cap applied to
	// tools' own rate flags.
	RPS float64
	// MaxRequests is the budget of cost units per run.
	MaxRequests int
	// CommandTimeout caps every command's timeout (and applies when a
	// command sets none).
	CommandTimeout time.Duration
	// Cost returns the budget cost of a command; nil means 1.
	Cost func(runner.Command) int
	// Clock is for tests; nil uses real time.
	Clock Clock
}

// Enabled reports whether any limit is configured.
func (c Config) Enabled() bool {
	return c.Concurrency > 0 || c.RPS > 0 || c.MaxRequests > 0 || c.CommandTimeout > 0
}

// Scheduler is the shared state behind the wrapped executor.
type Scheduler struct {
	cfg     Config
	sem     chan struct{}
	limiter *Limiter

	mu   sync.Mutex
	used int
}

// New builds a Scheduler from cfg.
func New(cfg Config) *Scheduler {
	s := &Scheduler{cfg: cfg}
	if cfg.Concurrency > 0 {
		s.sem = make(chan struct{}, cfg.Concurrency)
	}
	if cfg.RPS > 0 {
		s.limiter = NewLimiter(cfg.RPS, int(math.Ceil(cfg.RPS)), cfg.Clock)
	}
	return s
}

// Used returns the budget units consumed so far.
func (s *Scheduler) Used() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.used
}

// WrapExecutor returns exec decorated with the limits in cfg. When no limit
// is configured it returns exec unchanged.
func WrapExecutor(exec runner.Executor, cfg Config) runner.Executor {
	if !cfg.Enabled() {
		return exec
	}
	return &executor{next: exec, s: New(cfg)}
}

type executor struct {
	next runner.Executor
	s    *Scheduler
}

func (e *executor) Run(ctx context.Context, command runner.Command) (*runner.CommandResult, error) {
	s := e.s
	if s.sem != nil {
		select {
		case s.sem <- struct{}{}:
			defer func() { <-s.sem }()
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if err := s.limiter.Wait(ctx); err != nil {
		return nil, err
	}
	if err := s.reserve(command); err != nil {
		return nil, fmt.Errorf("%s: %w", command.Name, err)
	}

	command.Timeout = s.timeout(command.Timeout)
	command.Args = capRateFlags(command.Name, command.Args, s.cfg.RPS)
	return e.next.Run(ctx, command)
}

func (s *Scheduler) reserve(command runner.Command) error {
	if s.cfg.MaxRequests <= 0 {
		return nil
	}
	cost := 1
	if s.cfg.Cost != nil {
		cost = s.cfg.Cost(command)
	}
	if cost < 1 {
		cost = 1
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.used+cost > s.cfg.MaxRequests {
		return ErrBudgetExhausted
	}
	s.used += cost
	return nil
}

func (s *Scheduler) timeout(requested time.Duration) time.Duration {
	limit := s.cfg.CommandTimeout
	if limit <= 0 {
		return requested
	}
	if requested <= 0 || requested > limit {
		return limit
	}
	return requested
}

// rateFlags maps a tool to the flags it uses for requests/second. Only
// flags already present in args are touched.
var rateFlags = map[string][]string{
	"nuclei": {"-rate-limit", "-rl"},
	"katana": {"-rate-limit", "-rl"},
	"httpx":  {"-rate-limit", "-rl"},
	"ffuf":   {"-rate"},
	"naabu":  {"-rate"},
}

// capRateFlags lowers an existing integer rate flag value to at most rps. It
// never adds a flag and never raises a value. args is not mutated.
func capRateFlags(name string, args []string, rps float64) []string {
	if rps <= 0 {
		return args
	}
	flags := rateFlags[filepath.Base(name)]
	if len(flags) == 0 {
		return args
	}
	limit := int(rps)
	if limit < 1 {
		limit = 1
	}
	var out []string
	for i := 0; i+1 < len(args); i++ {
		for _, f := range flags {
			if args[i] != f {
				continue
			}
			v, err := strconv.Atoi(args[i+1])
			if err != nil || v <= limit {
				continue
			}
			if out == nil {
				out = append([]string(nil), args...)
			}
			out[i+1] = strconv.Itoa(limit)
		}
	}
	if out == nil {
		return args
	}
	return out
}
