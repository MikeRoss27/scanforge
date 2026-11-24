package app

import "testing"

func TestNormalizeToolVersion(t *testing.T) {
	tests := []struct {
		name, raw, want string
	}{
		{"httpx", "\x1b[1;34m[INF]\x1b[0m Current Version: v1.12.0\n", "v1.12.0"},
		{"dnsx banner", "   __| | _ __\n  / _' || '_ \\\n[INF] Current Version: 1.3.1\n", "1.3.1"},
		{"nuclei", "[INF] Nuclei Engine Version: v3.11.1\n", "v3.11.1"},
		{"nmap", "Nmap version 7.993 ( https://nmap.org )\nCompiled with: liblua-5.4.9 openssl-4.1.0\n", "7.993"},
		{"ffuf dev", "ffuf version: 2.1.0-dev\n", "2.1.0-dev"},
		{"gau", "gau version: 2.2.4\n", "2.2.4"},
		{"wafw00f random art", "   (  Woof! )\n  404 Hack Not Found\n                    ~ WAFW00F : v2.4.2 ~\n[+] The version of WAFW00F you have is v2.4.2\n", "v2.4.2"},
		{"number without version word", "tool 3.2.1 build\n", "3.2.1"},
		{"nothing", "banner only\n", ""},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeToolVersion(tt.raw); got != tt.want {
				t.Fatalf("normalizeToolVersion() = %q, want %q", got, tt.want)
			}
		})
	}
}
