package scope

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func writeScopeFile(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "scope.txt")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write scope file: %v", err)
	}

	return path
}

func TestLoadFromFileExactHost(t *testing.T) {
	path := writeScopeFile(t, "example.com\n")

	s, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !s.IsAllowed("example.com") {
		t.Fatal("expected example.com to be allowed")
	}

	if s.IsAllowed("other.com") {
		t.Fatal("expected other.com to be rejected")
	}
}

func TestLoadFromFileWildcard(t *testing.T) {
	path := writeScopeFile(t, "*.example.com\n")

	s, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !s.IsAllowed("api.example.com") {
		t.Fatal("expected api.example.com to be allowed")
	}

	if s.IsAllowed("example.com") {
		t.Fatal("expected bare example.com to be rejected for *.example.com")
	}
}

func TestLoadFromFileCIDR(t *testing.T) {
	path := writeScopeFile(t, "10.0.0.0/24\n")

	s, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !s.IsAllowed("10.0.0.42") {
		t.Fatal("expected 10.0.0.42 to be allowed")
	}

	if s.IsAllowed("10.0.1.1") {
		t.Fatal("expected 10.0.1.1 to be rejected")
	}
}

func TestNormalizeHostURL(t *testing.T) {
	path := writeScopeFile(t, "example.com\n")

	s, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !s.IsAllowed("https://example.com/path") {
		t.Fatal("expected normalized URL host to be allowed")
	}
}

func TestLoadFromFileCommentsAndEmptyLines(t *testing.T) {
	path := writeScopeFile(t, "# comment\n\nexample.com\n")

	s, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !s.IsAllowed("example.com") {
		t.Fatal("expected example.com to be allowed")
	}
}

func TestIsAllowedEmptyTarget(t *testing.T) {
	s := &Scope{ExactHosts: map[string]struct{}{}}

	if s.IsAllowed("") {
		t.Fatal("expected empty target to be rejected")
	}
}

func TestFromTargetExact(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		allowed []string
		denied  []string
	}{
		{
			name:    "URL becomes hostname",
			target:  "https://Example.COM:443/login",
			allowed: []string{"example.com", "https://example.com/other"},
			denied:  []string{"api.example.com", "other.com"},
		},
		{
			name:    "IPv4",
			target:  "192.0.2.10",
			allowed: []string{"192.0.2.10", "192.0.2.10:443"},
			denied:  []string{"192.0.2.11"},
		},
		{
			name:    "IPv6",
			target:  "2001:db8::10",
			allowed: []string{"2001:db8::10", "[2001:db8::10]:443"},
			denied:  []string{"2001:db8::11"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := FromTarget(tt.target, ModeExact, nil, nil)
			if err != nil {
				t.Fatalf("FromTarget() error = %v", err)
			}
			assertAllowed(t, s, tt.allowed, true)
			assertAllowed(t, s, tt.denied, false)
		})
	}
}

func TestFromTargetDomainIncludesRootAndSubdomains(t *testing.T) {
	s, err := FromTarget("https://Example.com/path", ModeDomain, nil, nil)
	if err != nil {
		t.Fatalf("FromTarget() error = %v", err)
	}

	assertAllowed(t, s, []string{
		"example.com",
		"api.example.com",
		"deep.api.example.com",
		"https://api.example.com/v1",
	}, true)
	assertAllowed(t, s, []string{
		"notexample.com",
		"example.com.evil.test",
		"192.0.2.1",
	}, false)
}

func TestFromTargetDomainRejectsIPAndCIDR(t *testing.T) {
	for _, target := range []string{"192.0.2.1", "2001:db8::1", "192.0.2.0/24", "com", "localhost"} {
		t.Run(target, func(t *testing.T) {
			if _, err := FromTarget(target, ModeDomain, nil, nil); err == nil {
				t.Fatalf("FromTarget(%q, ModeDomain) expected error", target)
			}
		})
	}
}

func TestFromTargetCIDROnlyAsAddition(t *testing.T) {
	if _, err := FromTarget("192.0.2.0/24", ModeExact, nil, nil); err == nil {
		t.Fatal("CIDR primary target should be rejected")
	}

	s, err := FromTarget("example.com", ModeExact, []string{"10.20.0.0/16"}, nil)
	if err != nil {
		t.Fatalf("FromTarget() error = %v", err)
	}
	assertAllowed(t, s, []string{"10.20.1.5", "10.20.1.5:8443"}, true)
	assertAllowed(t, s, []string{"10.21.1.5"}, false)
}

func TestFromTargetAdditions(t *testing.T) {
	s, err := FromTarget(
		"example.com",
		ModeExact,
		[]string{"api.other.test", "*.services.test", "198.51.100.0/24"},
		nil,
	)
	if err != nil {
		t.Fatalf("FromTarget() error = %v", err)
	}

	assertAllowed(t, s, []string{
		"example.com",
		"api.other.test",
		"v1.services.test",
		"198.51.100.42",
	}, true)
	assertAllowed(t, s, []string{
		"other.test",
		"services.test",
		"198.51.101.42",
	}, false)
}

func TestExclusionsAlwaysTakePriority(t *testing.T) {
	s, err := FromTarget(
		"example.com",
		ModeDomain,
		[]string{"192.0.2.0/24", "special.other.test"},
		[]string{"admin.example.com", "*.private.example.com", "192.0.2.128/25", "special.other.test"},
	)
	if err != nil {
		t.Fatalf("FromTarget() error = %v", err)
	}

	assertAllowed(t, s, []string{
		"example.com",
		"www.example.com",
		"private.example.com",
		"192.0.2.10",
	}, true)
	assertAllowed(t, s, []string{
		"admin.example.com",
		"api.private.example.com",
		"deep.api.private.example.com",
		"192.0.2.200",
		"special.other.test",
	}, false)
}

func TestFromTargetRejectsMalformedInput(t *testing.T) {
	tests := []struct {
		name       string
		target     string
		mode       Mode
		additions  []string
		exclusions []string
	}{
		{name: "empty target", target: "", mode: ModeExact},
		{name: "unknown mode", target: "example.com", mode: Mode("recursive")},
		{name: "wildcard target", target: "*.example.com", mode: ModeExact},
		{name: "bad hostname", target: "bad_host.example", mode: ModeExact},
		{name: "empty label", target: "api..example.com", mode: ModeExact},
		{name: "bad port", target: "example.com:99999", mode: ModeExact},
		{name: "port-scoped target", target: "example.com:443", mode: ModeExact},
		{name: "port-scoped IP", target: "192.0.2.10:443", mode: ModeExact},
		{name: "port-scoped IPv6", target: "[2001:db8::1]:443", mode: ModeExact},
		{name: "port-scoped addition", target: "example.com", mode: ModeExact, additions: []string{"api.other.test:8080"}},
		{name: "port-scoped exclusion", target: "example.com", mode: ModeExact, exclusions: []string{"admin.example.com:8443"}},
		{name: "URL credentials", target: "https://user:pass@example.com", mode: ModeExact},
		{name: "bad addition", target: "example.com", mode: ModeExact, additions: []string{"*.bad_host.test"}},
		{name: "bad CIDR", target: "example.com", mode: ModeExact, additions: []string{"10.0.0.0/99"}},
		{name: "bad exclusion", target: "example.com", mode: ModeExact, exclusions: []string{"!"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := FromTarget(tt.target, tt.mode, tt.additions, tt.exclusions); err == nil {
				t.Fatal("FromTarget() expected error")
			}
		})
	}
}

func TestEntriesAndWriteFileRoundTrip(t *testing.T) {
	s, err := FromTarget(
		"example.com",
		ModeDomain,
		[]string{"api.other.test", "192.0.2.0/24"},
		[]string{"admin.example.com", "*.internal.example.com", "192.0.2.128/25"},
	)
	if err != nil {
		t.Fatalf("FromTarget() error = %v", err)
	}

	wantEntries := []string{
		"api.other.test",
		"example.com",
		"*.example.com",
		"192.0.2.0/24",
		"!admin.example.com",
		"!*.internal.example.com",
		"!192.0.2.128/25",
	}
	if got := s.Entries(); !reflect.DeepEqual(got, wantEntries) {
		t.Fatalf("Entries() = %#v, want %#v", got, wantEntries)
	}

	path := filepath.Join(t.TempDir(), "effective-scope.txt")
	if err := s.WriteFile(path); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	loaded, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile() error = %v", err)
	}
	if got := loaded.Entries(); !reflect.DeepEqual(got, wantEntries) {
		t.Fatalf("round-trip Entries() = %#v, want %#v", got, wantEntries)
	}
	assertAllowed(t, loaded, []string{"www.example.com", "192.0.2.10"}, true)
	assertAllowed(t, loaded, []string{"admin.example.com", "x.internal.example.com", "192.0.2.200"}, false)
}

func TestLoadFromFileRejectsMalformedEntries(t *testing.T) {
	for _, entry := range []string{
		"bad_host.example",
		"api..example.com",
		"*.192.0.2.1",
		"10.0.0.0/99",
		"!",
		"example.com:443",
		"192.0.2.10:8080",
		"[2001:db8::1]:8443",
		"!admin.example.com:9443",
	} {
		t.Run(strings.ReplaceAll(entry, "/", "_"), func(t *testing.T) {
			path := writeScopeFile(t, entry+"\n")
			if _, err := LoadFromFile(path); err == nil {
				t.Fatalf("LoadFromFile() accepted malformed entry %q", entry)
			}
		})
	}
}

func TestWriteFileRejectsEmptyPath(t *testing.T) {
	s, err := FromTarget("example.com", ModeExact, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.WriteFile(" "); err == nil {
		t.Fatal("WriteFile() expected error")
	}

	var nilScope *Scope
	if err := nilScope.WriteFile(filepath.Join(t.TempDir(), "scope.txt")); err == nil {
		t.Fatal("nil Scope.WriteFile() expected error")
	}
}

func assertAllowed(t *testing.T, s *Scope, targets []string, want bool) {
	t.Helper()
	for _, target := range targets {
		if got := s.IsAllowed(target); got != want {
			t.Errorf("IsAllowed(%q) = %v, want %v", target, got, want)
		}
	}
}

// TestPortScopedFilteringStillWorks guards the scope filter used on open_ports
// artifacts: rejecting "host:port" as a scope entry must not break filtering
// "host:port" values against the host part.
func TestPortScopedFilteringStillWorks(t *testing.T) {
	s, err := FromTarget("example.com", ModeDomain, []string{"192.0.2.0/24"}, nil)
	if err != nil {
		t.Fatalf("FromTarget() error = %v", err)
	}
	assertAllowed(t, s, []string{
		"example.com:443",
		"www.example.com:8080",
		"192.0.2.10:8443",
	}, true)
	assertAllowed(t, s, []string{
		"outside.test:443",
		"192.0.3.1:8080",
	}, false)
}

// TestURLWithPortEntryAccepted: a URL carries its port inside the authority,
// so the hostname is what gets scoped and the URL itself stays a valid entry.
func TestURLWithPortEntryAccepted(t *testing.T) {
	path := writeScopeFile(t, "https://example.com:8443/path\n")
	s, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile() error = %v", err)
	}
	assertAllowed(t, s, []string{"example.com:8443", "example.com"}, true)
	assertAllowed(t, s, []string{"other.test"}, false)
}
