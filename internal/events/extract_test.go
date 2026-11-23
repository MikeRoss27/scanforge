package events

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestExtractArtifact(t *testing.T) {
	tests := []struct {
		name, artifact, content string
		want                    []Extracted
	}{
		{"subdomains skip IPs", "subdomains", "a.example.com\n10.0.0.1\n\n",
			[]Extracted{{Type: DNSName, Value: "a.example.com"}}},
		{"open ports", "open_ports", "a.example.com:443\n",
			[]Extracted{{Type: OpenPort, Value: "a.example.com:443"}}},
		{"alive urls add host", "alive_urls", "https://a.example.com\n",
			[]Extracted{{Type: LiveURL, Value: "https://a.example.com"}, {Type: DNSName, Value: "a.example.com"}}},
		{"crawl: js and host", "crawled_urls", "https://a.example.com/x.js?v=1\nhttps://b.example.com/page\nftp://x/y.js\n",
			[]Extracted{
				{Type: JSURL, Value: "https://a.example.com/x.js?v=1"}, {Type: DNSName, Value: "a.example.com"},
				{Type: DNSName, Value: "b.example.com"},
			}},
		{"js relative route carries scope ref", "js_secrets",
			`{"url":"https://a.example.com/app.js","kind":"endpoint","match":"/api/v1/users"}` + "\n",
			[]Extracted{
				{Type: JSURL, Value: "https://a.example.com/app.js"},
				{Type: APIRoute, Value: "https://a.example.com/api/v1/users", ScopeRef: "https://a.example.com"},
			}},
		{"js absolute route scoped by its own host", "js_secrets",
			`{"url":"https://a.example.com/app.js","kind":"endpoint","match":"https://evil.org/api"}` + "\n",
			[]Extracted{
				{Type: JSURL, Value: "https://a.example.com/app.js"},
				{Type: APIRoute, Value: "https://evil.org/api", ScopeRef: "https://evil.org"},
			}},
		{"js hosts", "js_secrets",
			`{"url":"https://a.example.com/app.js","kind":"cloud-storage","match":"storage.googleapis.com/b"}` + "\n" +
				`{"url":"https://a.example.com/app.js","kind":"internal-host","match":"10.0.0.5"}` + "\n",
			[]Extracted{
				{Type: JSURL, Value: "https://a.example.com/app.js"}, {Type: DNSName, Value: "storage.googleapis.com"},
				{Type: JSURL, Value: "https://a.example.com/app.js"},
			}},
		{"garbage lines ignored", "js_secrets", "not json\n{}\n", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "a")
			if err := os.WriteFile(p, []byte(tt.content), 0o644); err != nil {
				t.Fatal(err)
			}
			got, err := ExtractArtifact(tt.artifact, p)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %+v\nwant %+v", got, tt.want)
			}
		})
	}
	if got, err := ExtractArtifact("unknown", "/nonexistent"); got != nil || err != nil {
		t.Fatal("unknown artifacts are ignored")
	}
}
