package modules

import "testing"

func TestTargetPortAndProbe(t *testing.T) {
	for _, tt := range []struct {
		input    string
		port     int
		probe    string
		scopeTgt string
	}{
		{"http://127.0.0.1:8082", 8082, "127.0.0.1:8082", "http://127.0.0.1:8082"},
		{"https://Example.com:8443/app?x=1", 8443, "example.com:8443", "https://Example.com:8443/app?x=1"},
		{"example.com:8443", 8443, "example.com:8443", "example.com"},
		{"127.0.0.1:3000", 3000, "127.0.0.1:3000", "127.0.0.1"},
		{"[2001:db8::1]:8080", 8080, "[2001:db8::1]:8080", "2001:db8::1"},
		{"https://[2001:db8::1]:8443/", 8443, "[2001:db8::1]:8443", "https://[2001:db8::1]:8443/"},
		{"example.com", 0, "", "example.com"},
		{"https://example.com", 0, "", "https://example.com"},
		{"example.com:0", 0, "", "example.com:0"},
		{"example.com:70000", 0, "", "example.com:70000"},
		{"example.com:abc", 0, "", "example.com:abc"},
		{"https://user:pw@example.com:8443", 0, "", "https://user:pw@example.com:8443"},
	} {
		t.Run(tt.input, func(t *testing.T) {
			port, ok := TargetPort(tt.input)
			if port != tt.port || ok != (tt.port != 0) {
				t.Fatalf("TargetPort() = %d, %v; want %d", port, ok, tt.port)
			}
			probe, ok := TargetProbe(tt.input)
			if probe != tt.probe || ok != (tt.probe != "") {
				t.Fatalf("TargetProbe() = %q, %v; want %q", probe, ok, tt.probe)
			}
			if got := ScopeTarget(tt.input); got != tt.scopeTgt {
				t.Fatalf("ScopeTarget() = %q; want %q", got, tt.scopeTgt)
			}
		})
	}
}
