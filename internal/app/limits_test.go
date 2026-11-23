package app

import (
	"testing"
	"time"

	"github.com/MikeRoss27/scanforge/internal/config"
)

func TestEffectiveLimits(t *testing.T) {
	cfg := &config.Config{Limits: config.Limits{Concurrency: 4, RPS: 10, MaxRequests: 100, CommandTimeout: time.Minute}}
	tests := []struct {
		name string
		flag config.Limits
		want config.Limits
	}{
		{"config only", config.Limits{}, cfg.Limits},
		{"flags override", config.Limits{Concurrency: 2, RPS: 5}, config.Limits{Concurrency: 2, RPS: 5, MaxRequests: 100, CommandTimeout: time.Minute}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := effectiveLimits(cfg, RunOptions{Limits: tt.flag}); got != tt.want {
				t.Fatalf("got %+v want %+v", got, tt.want)
			}
		})
	}
	if err := (config.Limits{RPS: -1}).Validate(); err == nil {
		t.Fatal("negative limits must be rejected")
	}
}
