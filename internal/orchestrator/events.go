package orchestrator

import (
	"time"
)

type Event interface {
	isEvent()
}

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
}

type DeadlockEvent struct {
	Message string
}

// WarningEvent surfaces a module-level warning (e.g. a stage that ran on an
// empty input) while the scan is still live, so the operator is not left
// wondering why a module produced nothing.
type WarningEvent struct {
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

func (WaveStartEvent) isEvent()   {}
func (ModuleStartEvent) isEvent() {}
func (ModuleDoneEvent) isEvent()  {}
func (DeadlockEvent) isEvent()    {}
func (WarningEvent) isEvent()     {}
func (FindingEvent) isEvent()     {}
