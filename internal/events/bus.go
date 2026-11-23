package events

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	// DefaultMaxDepth bounds discovery chains (root = depth 0).
	DefaultMaxDepth = 5
	// DefaultBudget bounds the total number of accepted events per run.
	DefaultBudget = 10000

	eventsFile     = "events.jsonl"
	rejectionsFile = "scope-rejections.jsonl"
)

// ScopeChecker is the subset of *scope.Scope the bus needs. The bus cannot
// run without one: there is no allow-all mode.
type ScopeChecker interface {
	IsAllowed(target string) bool
}

// Handler receives an accepted event. Handlers may call Publish to emit
// derived events; those are queued and delivered after the current one.
type Handler func(Event)

// Disposition says what Publish did with an event.
type Disposition string

const (
	Delivered       Disposition = "delivered"
	Duplicate       Disposition = "duplicate"
	OutOfScope      Disposition = "out_of_scope"
	DepthExceeded   Disposition = "depth_exceeded"
	BudgetExhausted Disposition = "budget_exhausted"
)

// Options configures a Bus.
type Options struct {
	// MetaDir is the run's 00_meta directory (events.jsonl and
	// scope-rejections.jsonl live there). Required.
	MetaDir string
	// Scope is mandatory.
	Scope ScopeChecker
	// MaxDepth: zero means DefaultMaxDepth. Deeper events are dropped.
	MaxDepth int
	// Budget: zero means DefaultBudget. Max accepted events.
	Budget int
	// Now overrides the clock (tests).
	Now func() time.Time
}

// Stats are cumulative counters.
type Stats struct {
	Delivered, Duplicates, OutOfScope, DepthExceeded, BudgetExhausted int
}

// Bus has serialized admission and FIFO delivery, so the persisted order
// equals the delivery order.
type Bus struct {
	opts Options
	seen *seenSet

	mu       sync.Mutex
	cond     *sync.Cond
	subs     map[Type][]Handler
	all      []Handler
	depths   map[string]int // accepted ID -> depth
	rejected map[string]struct{}
	queue    []Event
	pending  int
	draining bool
	accepted int
	stats    Stats
}

// New creates a Bus.
func New(opts Options) (*Bus, error) {
	if opts.Scope == nil {
		return nil, errors.New("events: scope is mandatory")
	}
	if opts.MetaDir == "" {
		return nil, errors.New("events: meta dir is required")
	}
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = DefaultMaxDepth
	}
	if opts.Budget <= 0 {
		opts.Budget = DefaultBudget
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	b := &Bus{
		opts:     opts,
		seen:     newSeenSet(),
		subs:     make(map[Type][]Handler),
		depths:   make(map[string]int),
		rejected: make(map[string]struct{}),
	}
	b.cond = sync.NewCond(&b.mu)
	return b, nil
}

// Subscribe registers h for events of type t.
func (b *Bus) Subscribe(t Type, h Handler) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.subs[t] = append(b.subs[t], h)
}

// SubscribeAll registers h for every event type.
func (b *Bus) SubscribeAll(h Handler) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.all = append(b.all, h)
}

// Derive builds a child event of parent; Publish it to emit it.
func Derive(parent Event, t Type, value, source string) Event {
	return Event{Type: t, Value: value, Source: source, ParentID: parent.ID}
}

// Publish admits e (scope, depth, dedup, budget, persistence) and, if
// accepted, queues it for delivery. Delivery happens on the calling
// goroutine unless another goroutine is already draining; use Wait to block
// until everything queued has been delivered.
func (b *Bus) Publish(e Event) (Disposition, error) {
	if e.Type == "" {
		return "", errors.New("events: empty event type")
	}
	e.Value = Normalize(e.Type, e.Value)
	if e.Value == "" {
		return "", errors.New("events: empty event value")
	}
	e.ID = MakeID(e.Type, e.Value)

	b.mu.Lock()
	disp, err := b.admit(&e)
	if err == nil && disp == Delivered {
		b.queue = append(b.queue, e)
		b.pending++
	}
	b.mu.Unlock()
	if err != nil || disp != Delivered {
		return disp, err
	}
	b.drain()
	return Delivered, nil
}

// admit runs the gate; caller holds b.mu.
func (b *Bus) admit(e *Event) (Disposition, error) {
	e.Depth = 0
	if e.ParentID != "" {
		pd, ok := b.depths[e.ParentID]
		if !ok {
			return "", fmt.Errorf("events: unknown parent event %q", e.ParentID)
		}
		e.Depth = pd + 1
	}

	// 1. Scope: mandatory and first. Fails closed.
	target := e.ScopeRef
	if target == "" {
		target = e.Value
	}
	if !b.opts.Scope.IsAllowed(target) {
		if _, again := b.rejected[e.ID]; !again {
			if err := b.logRejection(*e); err != nil {
				return "", err
			}
			b.rejected[e.ID] = struct{}{}
		}
		b.stats.OutOfScope++
		return OutOfScope, nil
	}
	// 2. Depth.
	if e.Depth > b.opts.MaxDepth {
		b.stats.DepthExceeded++
		return DepthExceeded, nil
	}
	// 3. Dedup (checked first, marked only once persisted).
	if b.seen.has(e.ID) {
		b.stats.Duplicates++
		return Duplicate, nil
	}
	// 4. Budget.
	if b.accepted >= b.opts.Budget {
		b.stats.BudgetExhausted++
		return BudgetExhausted, nil
	}

	e.Timestamp = b.opts.Now().UTC()
	e.ScopeVerdict = VerdictAllowed
	if err := b.appendLine(eventsFile, e); err != nil {
		return "", fmt.Errorf("events: persist event: %w", err)
	}
	b.seen.add(e.ID)
	b.depths[e.ID] = e.Depth
	b.accepted++
	b.stats.Delivered++
	return Delivered, nil
}

func (b *Bus) drain() {
	b.mu.Lock()
	if b.draining {
		b.mu.Unlock()
		return
	}
	b.draining = true
	for len(b.queue) > 0 {
		e := b.queue[0]
		b.queue = b.queue[1:]
		handlers := append(append([]Handler(nil), b.subs[e.Type]...), b.all...)
		b.mu.Unlock()
		for _, h := range handlers {
			h(e)
		}
		b.mu.Lock()
		b.pending--
	}
	b.draining = false
	b.cond.Broadcast()
	b.mu.Unlock()
}

// Wait blocks until every accepted event has been delivered.
func (b *Bus) Wait() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for b.pending > 0 || b.draining {
		b.cond.Wait()
	}
}

// Stats returns a snapshot of the counters.
func (b *Bus) Stats() Stats {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.stats
}

func (b *Bus) appendLine(name string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(b.opts.MetaDir, name), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// scopeRejection mirrors the record written by modules.RunContext so both
// producers share one scope-rejections.jsonl format.
type scopeRejection struct {
	Timestamp string `json:"timestamp"`
	Artifact  string `json:"artifact"`
	Path      string `json:"path"`
	Value     string `json:"value"`
	Reason    string `json:"reason"`
}

func (b *Bus) logRejection(e Event) error {
	rec := scopeRejection{
		Timestamp: b.opts.Now().UTC().Format(time.RFC3339Nano),
		Artifact:  "event:" + string(e.Type),
		Path:      eventsFile,
		Value:     e.Value,
		Reason:    "outside configured scope",
	}
	if err := b.appendLine(rejectionsFile, rec); err != nil {
		return fmt.Errorf("events: log scope rejection: %w", err)
	}
	return nil
}
