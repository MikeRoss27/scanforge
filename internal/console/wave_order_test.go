package console

import (
	"bytes"
	"strings"
	"testing"

	"github.com/MikeRoss27/scanforge/internal/orchestrator"
)

func TestVerboseWaveHeadersNeverGoBackwards(t *testing.T) {
	var buf bytes.Buffer
	r := newTestRenderer(t, &buf, func(o *Options) { o.Verbosity = Verbose })
	// A level-6 batch starts before a late level-5 batch of another phase.
	r.Handle(orchestrator.WaveStartEvent{Wave: 6, Modules: []string{"jssecrets"}})
	r.Handle(orchestrator.ModuleStartEvent{Name: "jssecrets"})
	r.Handle(orchestrator.WaveStartEvent{Wave: 5, Modules: []string{"katana"}})
	r.Handle(orchestrator.ModuleStartEvent{Name: "katana"})
	out := buf.String()
	if !strings.Contains(out, "VULNERABILITY ANALYSIS · wave 6") {
		t.Fatalf("missing wave 6 header:\n%s", out)
	}
	if strings.Contains(out, "wave 5") {
		t.Errorf("wave 5 header printed after wave 6:\n%s", out)
	}
	if !strings.Contains(out, "WEB SURFACE") {
		t.Errorf("late phase header lost:\n%s", out)
	}
}
