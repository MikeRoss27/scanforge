package httpx

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestRequiresResolvedHosts(t *testing.T) {
	if got, want := New("").Requires(), []string{"resolved_hosts"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Requires() = %v, want %v", got, want)
	}
}

func TestSoftRequiresOpenPorts(t *testing.T) {
	if got, want := New("").SoftRequires(), []string{"open_ports"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("SoftRequires() = %v, want %v", got, want)
	}
}

func TestNonStandardPortTargets(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"skips default web ports", []string{"a.test:80", "a.test:443", "a.test:8080"}, []string{"a.test:8080"}},
		{"ignores garbage", []string{"", "nocolon", "a.test:", ":80", "a.test:abc", "a.test:70000", "a.test:0"}, nil},
		{"keeps ip targets", []string{"127.0.0.1:3000", " 10.0.0.1:8443 "}, []string{"127.0.0.1:3000", "10.0.0.1:8443"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := nonStandardPortTargets(tt.in); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWriteProbeTargets(t *testing.T) {
	tests := []struct {
		name      string
		hosts     string
		ports     *string
		wantN     int
		wantInput string
	}{
		{"merges and dedupes", "a.test\nb.test\n", ptr("a.test:80\na.test:8080\na.test:8080\nb.test:8443\n"), 3, "a.test\nb.test\na.test:8080\nb.test:8443\n"},
		{"only standard ports", "a.test\n", ptr("a.test:80\na.test:443\n"), 0, ""},
		{"missing ports file", "a.test\n", nil, 0, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			hosts := filepath.Join(dir, "hosts.txt")
			ports := filepath.Join(dir, "ports.txt")
			out := filepath.Join(dir, "merged.txt")
			if err := os.WriteFile(hosts, []byte(tt.hosts), 0o644); err != nil {
				t.Fatal(err)
			}
			if tt.ports != nil {
				if err := os.WriteFile(ports, []byte(*tt.ports), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			n, err := writeProbeTargets(hosts, ports, out)
			if err != nil || n != tt.wantN {
				t.Fatalf("n=%d err=%v, want n=%d", n, err, tt.wantN)
			}
			data, rerr := os.ReadFile(out)
			if tt.wantInput == "" {
				if rerr == nil {
					t.Fatalf("merged file written unexpectedly: %q", data)
				}
				return
			}
			if string(data) != tt.wantInput {
				t.Fatalf("merged = %q, want %q", data, tt.wantInput)
			}
		})
	}
}

func ptr(s string) *string { return &s }
