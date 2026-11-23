package app

import "github.com/MikeRoss27/scanforge/internal/config"

// effectiveLimits overlays the CLI limit flags on the config `limits:`
// section; a zero flag value keeps the config value.
func effectiveLimits(cfg *config.Config, opts RunOptions) config.Limits {
	limits := cfg.Limits
	if opts.Limits.Concurrency != 0 {
		limits.Concurrency = opts.Limits.Concurrency
	}
	if opts.Limits.RPS != 0 {
		limits.RPS = opts.Limits.RPS
	}
	if opts.Limits.MaxRequests != 0 {
		limits.MaxRequests = opts.Limits.MaxRequests
	}
	if opts.Limits.CommandTimeout != 0 {
		limits.CommandTimeout = opts.Limits.CommandTimeout
	}
	return limits
}
