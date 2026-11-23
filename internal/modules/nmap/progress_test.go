package nmap

import (
	"testing"

	"github.com/MikeRoss27/scanforge/internal/modules"
)

func TestParseTiming(t *testing.T) {
	tests := []struct {
		line string
		ok   bool
		want timing
	}{
		{"Service scan Timing: About 45.67% done; ETC: 23:31 (0:00:20 remaining)", true, timing{"Service scan", 45.67}},
		{"SYN Stealth Scan Timing: About 3.10% done; ETC: 23:40 (0:09:12 remaining)", true, timing{"SYN Stealth Scan", 3.10}},
		{"NSE Timing: About 99.20% done; ETC: 23:31 (0:00:00 remaining)", true, timing{"NSE", 99.20}},
		{"Connect Scan Timing: About 100% done", true, timing{"Connect Scan", 100}},
		{"Stats: 0:00:12 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan", false, timing{}},
		{"443/tcp open  ssl/http nginx", false, timing{}},
		{"", false, timing{}},
	}
	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			got, ok := parseTiming(tt.line)
			if ok != tt.ok || (ok && got != tt.want) {
				t.Fatalf("parseTiming(%q) = %+v, %v; want %+v, %v", tt.line, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestScanProgressAggregates(t *testing.T) {
	var events []modules.ModuleProgressEvent
	p := newScanProgress("nmap", 2, func(e modules.ModuleProgressEvent) { events = append(events, e) })

	p.observe("host-0001", "banner line")
	if len(events) != 0 {
		t.Fatalf("non-timing line emitted %+v", events)
	}
	p.observe("host-0001", "Service scan Timing: About 40.00% done; ETC: 23:31")
	p.observe("host-0002", "SYN Stealth Scan Timing: About 60.00% done; ETC: 23:31")
	last := events[len(events)-1]
	if last.Current != 0 || last.Total != 2 || last.Unit != "hosts" || last.Message != "service scan 50%" {
		t.Fatalf("unexpected aggregate %+v", last)
	}

	p.jobDone("host-0001")
	p.hostDone()
	last = events[len(events)-1]
	if last.Current != 1 || last.Message != "syn stealth scan 60%" {
		t.Fatalf("unexpected after host done %+v", last)
	}

	p.jobDone("host-0002")
	p.hostDone()
	last = events[len(events)-1]
	if last.Current != 2 || last.Message != "" {
		t.Fatalf("unexpected final %+v", last)
	}
}
