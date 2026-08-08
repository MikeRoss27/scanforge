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

func (WaveStartEvent) isEvent()   {}
func (ModuleStartEvent) isEvent() {}
func (ModuleDoneEvent) isEvent()  {}
func (DeadlockEvent) isEvent()    {}
