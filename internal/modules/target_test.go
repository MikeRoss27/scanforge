package modules

import "testing"

func TestTargetHost(t *testing.T) {
	for _, tt := range []struct{ input, want string }{
		{"example.com", "example.com"},
		{" https://Example.COM.:8443/path?q=1#fragment ", "example.com"},
		{"example.com:443", "example.com"},
		{"https://[2001:db8::1]:443/path", "2001:db8::1"},
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"", ""},
		{"https:///path", ""},
		{"example.com/path", ""},
		{"https://user:pass@example.com", ""},
	} {
		t.Run(tt.input, func(t *testing.T) {
			got, err := TargetHost(tt.input)
			if (err != nil) != (tt.want == "") || got != tt.want {
				t.Fatalf("TargetHost(%q) = %q, %v; want %q", tt.input, got, err, tt.want)
			}
		})
	}
}
