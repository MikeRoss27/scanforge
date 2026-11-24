package orchestrator

import (
	"time"

	"github.com/MikeRoss27/scanforge/internal/runner"
)

type Event interface {
	isEvent()
}

// WaveStartEvent describes a batch dispatched from one static DAG level. The
// level remains useful in verbose output and plans, but it is not an execution
// barrier: later-level modules may start while an unrelated earlier module is
// still running.
type WaveStartEvent struct {
	Wave    int
	Modules []string
}

type ModuleStartEvent struct {
	Name string
}

type ModuleDoneEvent struct {
	Name    string
	Status  string
	Dur     time.Duration
	Failed  bool
	Summary string
	// Reason explains a status the module chose itself, e.g. why it
	// skipped ("no WordPress detected").
	Reason string
	// Error carries the underlying failure message when the module failed,
	// so the console can render an actionable error block instead of a bare
	// status word.
	Error string
	// Kind classifies why Error is non-empty (missing binary, timeout,
	// cancellation, or unknown), so the console can give advice tailored to
	// the actual cause instead of the same generic hint for every failure.
	// Zero value (FailureUnknown) when Error is empty.
	Kind runner.FailureKind
}

// DeadlockEvent is emitted when no module can run anymore because its
// dependencies failed (or the run was aborted): remaining modules are
// marked skipped and the scan ends gracefully.
type DeadlockEvent struct {
	Message string
}

// WarningEvent surfaces a module-level warning (e.g. a stage that ran on an
// empty input) while the scan is still live, so the operator is not left
// wondering why a module produced nothing.
type WarningEvent struct {
	Message string
}

// NoticeEvent is an informational line about orchestrator-level work that is
// not a module (e.g. the recursive discovery follow-up passes).
type NoticeEvent struct {
	Message string
}

// FindingEvent is emitted the moment a module discovers a vulnerability or
// exposure, ahead of the module's own completion (which can be minutes away
// for long-running scanners like nuclei).
type FindingEvent struct {
	Module   string
	Severity string
	Title    string
	Target   string
	Detail   string
}

// ModuleProgressEvent carries live progress published by a module while it
// runs. It only exists for modules that expose reliable metrics — the
// console renders it as a volatile progress line and never invents numbers
// for modules that stay silent.
type ModuleProgressEvent struct {
	Name    string
	Current int
	Total   int
	Unit    string
	Message string
}

func (WaveStartEvent) isEvent()      {}
func (ModuleStartEvent) isEvent()    {}
func (ModuleDoneEvent) isEvent()     {}
func (ModuleProgressEvent) isEvent() {}
func (DeadlockEvent) isEvent()       {}
func (WarningEvent) isEvent()        {}
func (NoticeEvent) isEvent()         {}
func (FindingEvent) isEvent()        {}
