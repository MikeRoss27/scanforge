package scheduler

import (
	"context"
	"math"
	"sync"
	"time"
)

// Clock abstracts time so the limiter can be tested without real sleeping.
type Clock interface {
	Now() time.Time
	// Sleep blocks for d or until ctx is done, returning ctx.Err() in the
	// latter case.
	Sleep(ctx context.Context, d time.Duration) error
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

func (realClock) Sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Limiter is an in-memory token bucket refilled at rate tokens per second
// with a burst capacity. It is safe for concurrent use.
type Limiter struct {
	clock Clock
	rate  float64
	burst float64

	mu     sync.Mutex
	tokens float64
	last   time.Time
}

// NewLimiter returns a limiter allowing rate events per second. Burst is the
// bucket capacity; values below 1 are raised to 1. A nil clock uses real
// time. rate <= 0 yields a limiter that never blocks.
func NewLimiter(rate float64, burst int, clock Clock) *Limiter {
	if clock == nil {
		clock = realClock{}
	}
	if burst < 1 {
		burst = 1
	}
	return &Limiter{clock: clock, rate: rate, burst: float64(burst), tokens: float64(burst), last: clock.Now()}
}

// Wait blocks until one token is available or ctx is done.
func (l *Limiter) Wait(ctx context.Context) error {
	if l == nil || l.rate <= 0 {
		return ctx.Err()
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		wait := l.reserve()
		if wait <= 0 {
			return nil
		}
		if err := l.clock.Sleep(ctx, wait); err != nil {
			return err
		}
	}
}

// reserve takes a token if available (returning 0) or reports how long to
// wait before one should be.
func (l *Limiter) reserve() time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock.Now()
	if elapsed := now.Sub(l.last); elapsed > 0 {
		l.tokens = math.Min(l.burst, l.tokens+elapsed.Seconds()*l.rate)
		l.last = now
	}
	if l.tokens >= 1 {
		l.tokens--
		return 0
	}
	need := (1 - l.tokens) / l.rate
	return time.Duration(math.Ceil(need * float64(time.Second)))
}
