package scheduler

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MikeRoss27/scanforge/internal/runner"
)

type fakeClock struct {
	mu    sync.Mutex
	now   time.Time
	slept time.Duration
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *fakeClock) Sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.slept += d
	c.mu.Unlock()
	return nil
}

type fakeExec struct {
	mu       sync.Mutex
	commands []runner.Command
	running  int32
	peak     int32
	hold     time.Duration
}

func (f *fakeExec) Run(_ context.Context, c runner.Command) (*runner.CommandResult, error) {
	n := atomic.AddInt32(&f.running, 1)
	for {
		p := atomic.LoadInt32(&f.peak)
		if n <= p || atomic.CompareAndSwapInt32(&f.peak, p, n) {
			break
		}
	}
	time.Sleep(f.hold)
	atomic.AddInt32(&f.running, -1)
	f.mu.Lock()
	f.commands = append(f.commands, c)
	f.mu.Unlock()
	return &runner.CommandResult{Command: c}, nil
}

func TestWrapExecutorDisabledReturnsSame(t *testing.T) {
	f := &fakeExec{}
	if got := WrapExecutor(f, Config{}); got != runner.Executor(f) {
		t.Fatal("expected passthrough when no limits are set")
	}
}

func TestBudget(t *testing.T) {
	tests := []struct {
		name      string
		max, runs int
		cost      func(runner.Command) int
		wantOK    int
	}{
		{"within budget", 5, 3, nil, 3},
		{"exact", 3, 3, nil, 3},
		{"exhausted", 2, 4, nil, 2},
		{"custom cost", 10, 5, func(runner.Command) int { return 4 }, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeExec{}
			ex := WrapExecutor(f, Config{MaxRequests: tt.max, Cost: tt.cost})
			ok := 0
			for i := 0; i < tt.runs; i++ {
				_, err := ex.Run(context.Background(), runner.Command{Name: "x"})
				if err == nil {
					ok++
				} else if !errors.Is(err, ErrBudgetExhausted) {
					t.Fatalf("unexpected error %v", err)
				}
			}
			if ok != tt.wantOK || len(f.commands) != tt.wantOK {
				t.Fatalf("ok=%d executed=%d want %d", ok, len(f.commands), tt.wantOK)
			}
		})
	}
}

func TestTimeout(t *testing.T) {
	tests := []struct {
		name      string
		limit, in time.Duration
		want      time.Duration
	}{
		{"caps longer", time.Minute, time.Hour, time.Minute},
		{"keeps shorter", time.Minute, time.Second, time.Second},
		{"applies when none", time.Minute, 0, time.Minute},
		{"unset limit keeps value", 0, time.Hour, time.Hour},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeExec{}
			ex := WrapExecutor(f, Config{CommandTimeout: tt.limit, MaxRequests: 100})
			if _, err := ex.Run(context.Background(), runner.Command{Name: "x", Timeout: tt.in}); err != nil {
				t.Fatal(err)
			}
			if got := f.commands[0].Timeout; got != tt.want {
				t.Fatalf("timeout=%v want %v", got, tt.want)
			}
		})
	}
}

func TestConcurrencyBound(t *testing.T) {
	f := &fakeExec{hold: 5 * time.Millisecond}
	ex := WrapExecutor(f, Config{Concurrency: 2})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = ex.Run(context.Background(), runner.Command{Name: "x"})
		}()
	}
	wg.Wait()
	if f.peak > 2 || len(f.commands) != 8 {
		t.Fatalf("peak=%d executed=%d", f.peak, len(f.commands))
	}
}

func TestCancelWhileWaitingForSlot(t *testing.T) {
	f := &fakeExec{}
	s := New(Config{Concurrency: 1})
	s.sem <- struct{}{} // occupy the only slot
	ex := &executor{next: f, s: s}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ex.Run(ctx, runner.Command{Name: "x"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
	if len(f.commands) != 0 {
		t.Fatal("command must not run")
	}
}

func TestRateLimitsLaunches(t *testing.T) {
	clk := &fakeClock{now: time.Unix(0, 0)}
	f := &fakeExec{}
	ex := WrapExecutor(f, Config{RPS: 10, Clock: clk}) // burst 10
	for i := 0; i < 15; i++ {
		if _, err := ex.Run(context.Background(), runner.Command{Name: "x"}); err != nil {
			t.Fatal(err)
		}
	}
	// 10 from burst, 5 more at 10/s => about 500ms of fake waiting.
	if clk.slept < 490*time.Millisecond || clk.slept > 520*time.Millisecond {
		t.Fatalf("slept=%v", clk.slept)
	}
}

func TestCapRateFlags(t *testing.T) {
	tests := []struct {
		name string
		tool string
		args []string
		rps  float64
		want []string
	}{
		{"nuclei capped", "/usr/bin/nuclei", []string{"-l", "f", "-rate-limit", "150"}, 20, []string{"-l", "f", "-rate-limit", "20"}},
		{"lower kept", "katana", []string{"-rate-limit", "5"}, 20, []string{"-rate-limit", "5"}},
		{"never added", "nuclei", []string{"-l", "f"}, 20, []string{"-l", "f"}},
		{"ffuf rate", "ffuf", []string{"-rate", "500"}, 50, []string{"-rate", "50"}},
		{"unknown tool", "nmap", []string{"-rate", "500"}, 50, []string{"-rate", "500"}},
		{"disabled", "nuclei", []string{"-rate-limit", "150"}, 0, []string{"-rate-limit", "150"}},
		{"fractional floors to 1", "naabu", []string{"-rate", "100"}, 0.5, []string{"-rate", "1"}},
		{"non-numeric untouched", "httpx", []string{"-rl", "x"}, 10, []string{"-rl", "x"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orig := append([]string(nil), tt.args...)
			got := capRateFlags(tt.tool, tt.args, tt.rps)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %v want %v", got, tt.want)
			}
			if !reflect.DeepEqual(tt.args, orig) {
				t.Fatal("input args mutated")
			}
		})
	}
}

func TestWrapperAppliesRateCap(t *testing.T) {
	f := &fakeExec{}
	ex := WrapExecutor(f, Config{RPS: 30, Clock: &fakeClock{now: time.Unix(0, 0)}})
	_, _ = ex.Run(context.Background(), runner.Command{Name: "nuclei", Args: []string{"-rate-limit", "150"}})
	if got := f.commands[0].Args[1]; got != "30" {
		t.Fatalf("rate=%s", got)
	}
}
