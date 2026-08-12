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
func (FindingEvent) isEvent()     {}
