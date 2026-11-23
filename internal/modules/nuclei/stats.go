package nuclei

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/MikeRoss27/scanforge/internal/modules"
)

// statsIntervalSeconds is how often nuclei prints a statistics line
// (-stats-interval). Five seconds keeps the progress line lively without
// flooding the stderr log on hour-long scans.
const statsIntervalSeconds = 5

// scanStats is one -stats-json line. nuclei encodes every counter as a
// string ("requests":"120"), but older builds and forks emit raw numbers,
// so each field goes through statValue.
type scanStats struct {
	Requests int
	Total    int
	Percent  int
	Matched  int
	Errors   int
	RPS      int
	Hosts    int
}

// parseStats decodes one stderr line. ok is false for anything that is not a
// stats object (nuclei's own log lines, partial writes, unrelated JSON).
func parseStats(line string) (scanStats, bool) {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "{") {
		return scanStats{}, false
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return scanStats{}, false
	}
	// requests + total are what make a line a stats line; without them
	// there is no progress to report.
	requests, okReq := statValue(raw["requests"])
	total, okTotal := statValue(raw["total"])
	if !okReq || !okTotal {
		return scanStats{}, false
	}
	s := scanStats{Requests: requests, Total: total}
	var okPct bool
	if s.Percent, okPct = statValue(raw["percent"]); !okPct && total > 0 {
		s.Percent = min(100, requests*100/total)
	}
	s.Matched, _ = statValue(raw["matched"])
	s.Errors, _ = statValue(raw["errors"])
	s.RPS, _ = statValue(raw["rps"])
	s.Hosts, _ = statValue(raw["hosts"])
	return s, true
}

// statValue reads a counter encoded either as a JSON string or a number.
func statValue(raw json.RawMessage) (int, bool) {
	if len(raw) == 0 {
		return 0, false
	}
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		var num float64
		if err := json.Unmarshal(raw, &num); err != nil {
			return 0, false
		}
		return int(num), true
	}
	text = strings.TrimSuffix(strings.TrimSpace(text), "%")
	if v, err := strconv.Atoi(text); err == nil {
		return v, true
	}
	if f, err := strconv.ParseFloat(text, 64); err == nil {
		return int(f), true
	}
	return 0, false
}

// progressEvent maps nuclei's counters onto the console progress model:
// real requests done out of the planned total, plus a short summary of the
// remaining measured values.
func (s scanStats) progressEvent(name string) modules.ModuleProgressEvent {
	current := s.Requests
	if s.Total > 0 && current > s.Total {
		current = s.Total
	}
	parts := []string{}
	if s.Total > 0 {
		parts = append(parts, fmt.Sprintf("%d%%", s.Percent))
	}
	parts = append(parts, fmt.Sprintf("%d matched", s.Matched))
	if s.RPS > 0 {
		parts = append(parts, fmt.Sprintf("%d rps", s.RPS))
	}
	if s.Errors > 0 {
		parts = append(parts, fmt.Sprintf("%d errors", s.Errors))
	}
	return modules.ModuleProgressEvent{
		Name:    name,
		Current: current,
		Total:   s.Total,
		Unit:    "requests",
		Message: strings.Join(parts, " · "),
	}
}
