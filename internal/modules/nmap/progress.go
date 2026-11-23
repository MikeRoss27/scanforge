package nmap

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/MikeRoss27/scanforge/internal/modules"
)

// statsEvery is nmap's --stats-every cadence.
const statsEvery = "10s"

// timingLine matches nmap's periodic status line, e.g.
//
//	Service scan Timing: About 45.67% done; ETC: 23:31 (0:00:20 remaining)
//	SYN Stealth Scan Timing: About 3.10% done; ETC: 23:40 (0:09:12 remaining)
var timingLine = regexp.MustCompile(`^\s*(.+?) Timing: About ([0-9]+(?:\.[0-9]+)?)% done`)

// timing is one parsed status line.
type timing struct {
	Phase   string
	Percent float64
}

// parseTiming decodes one nmap stdout line; ok is false for anything else
// (port tables, "Stats:" headers, banners).
func parseTiming(line string) (timing, bool) {
	match := timingLine.FindStringSubmatch(line)
	if match == nil {
		return timing{}, false
	}
	pct, err := strconv.ParseFloat(match[2], 64)
	if err != nil {
		return timing{}, false
	}
	if pct > 100 {
		pct = 100
	}
	return timing{Phase: strings.TrimSpace(match[1]), Percent: pct}, true
}

// scanProgress aggregates per-command status lines into one module-level
// progress event: hosts finished out of the total, plus the current phase
// and the average completion of the commands still running. nmap restarts
// its percentage at every phase, so the percent is informative only; the
// host counter is the monotonic part.
type scanProgress struct {
	name  string
	total int
	emit  func(modules.ModuleProgressEvent)

	mu      sync.Mutex
	done    int
	running map[string]timing
}

func newScanProgress(name string, total int, emit func(modules.ModuleProgressEvent)) *scanProgress {
	return &scanProgress{name: name, total: total, emit: emit, running: map[string]timing{}}
}

// observe records a stdout line of the command identified by job.
func (p *scanProgress) observe(job, line string) {
	t, ok := parseTiming(line)
	if !ok {
		return
	}
	p.mu.Lock()
	p.running[job] = t
	ev := p.eventLocked()
	p.mu.Unlock()
	p.emit(ev)
}

// jobDone forgets a finished command's last status line.
func (p *scanProgress) jobDone(job string) {
	p.mu.Lock()
	delete(p.running, job)
	p.mu.Unlock()
}

// hostDone counts one host whose every port chunk has finished.
func (p *scanProgress) hostDone() {
	p.mu.Lock()
	p.done++
	ev := p.eventLocked()
	p.mu.Unlock()
	p.emit(ev)
}

func (p *scanProgress) eventLocked() modules.ModuleProgressEvent {
	ev := modules.ModuleProgressEvent{Name: p.name, Current: min(p.done, p.total), Total: p.total, Unit: "hosts"}
	if len(p.running) == 0 {
		return ev
	}
	jobs := make([]string, 0, len(p.running))
	var sum float64
	for job, t := range p.running {
		jobs = append(jobs, job)
		sum += t.Percent
	}
	// Deterministic phase label: the lexically first running job.
	sort.Strings(jobs)
	phase := strings.ToLower(p.running[jobs[0]].Phase)
	ev.Message = fmt.Sprintf("%s %d%%", phase, int(sum/float64(len(p.running))))
	return ev
}
