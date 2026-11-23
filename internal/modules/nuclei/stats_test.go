package nuclei

import "testing"

func TestParseStats(t *testing.T) {
	tests := []struct {
		name string
		line string
		ok   bool
		want scanStats
	}{
		{
			name: "nuclei v3 string counters",
			line: `{"duration":"0:00:10","errors":"2","hosts":"2","matched":"1","percent":"34","requests":"5880","rps":"587","startedAt":"2026-11-21T23:28:58.1+01:00","templates":"3","total":"17292"}`,
			ok:   true,
			want: scanStats{Requests: 5880, Total: 17292, Percent: 34, Matched: 1, Errors: 2, RPS: 587, Hosts: 2},
		},
		{
			name: "numeric counters",
			line: `{"requests":10,"total":40,"percent":25,"matched":0,"rps":3.7}`,
			ok:   true,
			want: scanStats{Requests: 10, Total: 40, Percent: 25, RPS: 3},
		},
		{
			name: "percent derived when absent",
			line: `{"requests":"50","total":"200"}`,
			ok:   true,
			want: scanStats{Requests: 50, Total: 200, Percent: 25},
		},
		{name: "log line", line: `[INF] Current nuclei version: v3.4.2`},
		{name: "partial json", line: `{"requests":"5`},
		{name: "unrelated json", line: `{"template-id":"x","host":"h"}`},
		{name: "empty", line: ``},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseStats(tt.line)
			if ok != tt.ok {
				t.Fatalf("ok = %v, want %v", ok, tt.ok)
			}
			if ok && got != tt.want {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestStatsProgressEvent(t *testing.T) {
	ev := scanStats{Requests: 5880, Total: 17292, Percent: 34, Matched: 1, RPS: 587}.progressEvent("nuclei")
	if ev.Name != "nuclei" || ev.Current != 5880 || ev.Total != 17292 || ev.Unit != "requests" {
		t.Fatalf("unexpected event %+v", ev)
	}
	if ev.Message != "34% · 1 matched · 587 rps" {
		t.Fatalf("message = %q", ev.Message)
	}
	clamped := scanStats{Requests: 120, Total: 100, Percent: 100}.progressEvent("nuclei")
	if clamped.Current != 100 {
		t.Fatalf("current not clamped: %+v", clamped)
	}
}
