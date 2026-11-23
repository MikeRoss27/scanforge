// Package runindextest builds run-store fixtures for tests.
package runindextest

import (
	"os"
	"path/filepath"
	"testing"
)

const (
	LeakedSecret   = "AKIAIOSFODNN7EXAMPLE"
	OperatorBearer = "opsecret-token-123456"
	RunID          = "example.com/2026-01-01_00-00-00"
)

// WriteFixture creates a workspace with one run and returns its root.
func WriteFixture(t testing.TB) string {
	t.Helper()
	ws := t.TempDir()
	dir := filepath.Join(ws, "example.com", "2026-01-01_00-00-00")
	for _, d := range []string{"00_meta", "06_vulns", "02_http"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(rel, body string) {
		if err := os.WriteFile(filepath.Join(dir, rel), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("00_meta/manifest.json", `{"id":"2026-01-01_00-00-00","target":"example.com","profile":"web","started_at":"2026-01-01T00:00:00Z","status":"completed","scope_source":"explicit-file","scope_mode":"file","modules":[{"name":"nuclei","status":"completed"}],"outputs":{}}`)
	write("00_meta/commands.log", "$ nuclei -u https://example.com -H 'Authorization: Bearer "+OperatorBearer+"' -H 'Cookie: sid=sessionvalue99'\n")
	write("report.json", `{"target":"example.com","profile":"web","status":"completed","assets":{"www.example.com":{"name":"www.example.com","technologies":["nginx"],"vulnerabilities":[{"source":"jssecrets","template_id":"aws-key","title":"AWS key in JS","severity":"high","matched_at":"https://www.example.com/app.js","evidence":"`+LeakedSecret+`"},{"source":"nuclei","template_id":"x","title":"Echo","severity":"low","matched_at":"https://www.example.com/","evidence":"echoed `+OperatorBearer+`"}]}}}`)
	write("06_vulns/nuclei.jsonl", `{"request":"GET / Authorization: Bearer `+OperatorBearer+` cookie sessionvalue99","leak":"`+LeakedSecret+`"}`+"\n")
	return ws
}
