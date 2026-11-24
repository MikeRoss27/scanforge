package console

import (
	"sort"
	"strconv"
	"strings"
)

// modulePhase buckets every integrated module into a pipeline phase. The
// header is derived from the modules that actually start in each wave of
// the DAG, so the separators always describe what is really running.
var modulePhase = map[string]string{
	"subfinder":     "DISCOVERY",
	"dnsbrute":      "DISCOVERY",
	"ctlogs":        "DISCOVERY",
	"asnmap":        "RESOLUTION",
	"gau":           "DISCOVERY",
	"dnsx":          "RESOLUTION",
	"naabu":         "PORTS",
	"nmap":          "PORTS",
	"httpx":         "WEB SURFACE",
	"tlsx":          "WEB SURFACE",
	"whatweb":       "WEB SURFACE",
	"wafw00f":       "WEB SURFACE",
	"httpcheck":     "WEB SURFACE",
	"katana":        "WEB SURFACE",
	"ffuf":          "WEB SURFACE",
	"attacksurface": "WEB SURFACE",
	"screenshot":    "WEB SURFACE",
	"jssecrets":     "VULNERABILITY ANALYSIS",
	"jsverify":      "VULNERABILITY ANALYSIS",
	"payloadgen":    "VULNERABILITY ANALYSIS",
	"techcve":       "VULNERABILITY ANALYSIS",
	"nuclei":        "VULNERABILITY ANALYSIS",
}

// phaseOrder is the canonical left-to-right order of pipeline phases. A wave
// can mix independent phases (ports and web surface often run together), so
// the header joins them instead of pretending the first module describes the
// whole wave.
var phaseOrder = []string{"DISCOVERY", "RESOLUTION", "PORTS", "WEB SURFACE", "VULNERABILITY ANALYSIS"}

// phaseFor derives the phase label of a wave from its module list. Unknown
// modules yield no phase (no fake headers for pipelines ScanForge does not
// know); mixed waves list every phase they actually run.
func phaseFor(modules []string) string {
	seen := map[string]bool{}
	var phases []string
	for _, name := range modules {
		phase, ok := modulePhase[name]
		if !ok || seen[phase] {
			continue
		}
		seen[phase] = true
		phases = append(phases, phase)
	}
	sort.Slice(phases, func(i, j int) bool {
		return phaseWeight(phases[i]) < phaseWeight(phases[j])
	})
	return strings.Join(phases, " · ")
}

func phaseWeight(phase string) int {
	for i, name := range phaseOrder {
		if name == phase {
			return i
		}
	}
	return len(phaseOrder)
}

// phaseHeader renders "── DISCOVERY ───────────…" with the wave number added
// at -v, e.g. "── DISCOVERY · wave 2 ───…".
func (r *Renderer) phaseHeader(phase string, wave int) string {
	label := phase
	if r.verbosity >= Verbose && wave > 0 {
		label += " · wave " + itoa(wave)
	}
	return r.th.rule(label, r.ruleWidth())
}

// ruleWidth is the separator width: full terminal width minus a breathing
// margin, capped at the width the reference layouts were designed for.
func (r *Renderer) ruleWidth() int {
	width := r.term.Width - 2
	if width > 96 {
		width = 96
	}
	if width < 20 {
		width = 20
	}
	return width
}

func itoa(n int) string {
	return strconv.Itoa(n)
}
