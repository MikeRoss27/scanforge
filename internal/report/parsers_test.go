package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseHosts(t *testing.T) {
	content := "example.com\nhttps://sub.example.com\n"
	path := writeTempFile(t, content)

	rep := NewReport("example.com", "test")
	err := ParseHosts(path, rep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(rep.Assets) != 2 {
		t.Fatalf("expected 2 assets, got %d", len(rep.Assets))
	}
	if _, ok := rep.Assets["example.com"]; !ok {
		t.Error("missing example.com")
	}
	if _, ok := rep.Assets["sub.example.com"]; !ok {
		t.Error("missing sub.example.com")
	}
}

func TestParsePorts(t *testing.T) {
	content := "example.com:80\nexample.com:443\nsub.example.com:8080\n"
	path := writeTempFile(t, content)

	rep := NewReport("example.com", "test")
	err := ParsePorts(path, rep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	asset := rep.GetOrCreateAsset("example.com")
	if len(asset.Ports) != 2 {
		t.Fatalf("expected 2 ports on example.com, got %d", len(asset.Ports))
	}
	if asset.Ports[80].Number != 80 {
		t.Error("missing port 80")
	}
}

func TestParseHttpx(t *testing.T) {
	content := `{"url":"https://example.com","host":"example.com","tech":["Nginx","PHP"],"a":["192.0.2.10"],"cname":["edge.example.net"],"cdn_name":"cloudfront","status_code":200,"title":"Home","webserver":"nginx","content_type":"text/html","content_length":42,"time":"120ms","favicon":1234,"asn":{"as_number":"AS64500","as_name":"EXAMPLE","as_country":"FR"}}
{"url":"http://example.com","host":"example.com","tech":["Nginx"]}
`
	path := writeTempFile(t, content)

	rep := NewReport("example.com", "test")
	err := ParseHttpx(path, rep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	asset := rep.GetOrCreateAsset("example.com")
	if len(asset.Technologies) != 2 {
		t.Fatalf("expected 2 unique technologies, got %d", len(asset.Technologies))
	}
	if len(asset.HTTP) != 2 || asset.HTTP[0].StatusCode != 200 || asset.HTTP[0].Favicon != "1234" {
		t.Fatalf("HTTP enrichment not parsed: %+v", asset.HTTP)
	}
	if len(asset.IPs) != 1 || len(asset.CNAMEs) != 1 || len(asset.CDN) != 1 || len(asset.ASN) != 1 {
		t.Fatalf("network enrichment not parsed: %+v", asset)
	}
}

func TestParseDnsx(t *testing.T) {
	path := writeTempFile(t, `{"host":"api.example.com","a":["192.0.2.10"],"aaaa":["2001:db8::10"],"cname":["edge.example.net"],"cdn-name":"fastly","asn":{"as-number":"AS64500","as-name":"EXAMPLE","as-country":"FR"}}`+"\n")
	rep := NewReport("example.com", "test")
	if err := ParseDnsx(path, rep); err != nil {
		t.Fatal(err)
	}
	asset := rep.Assets["api.example.com"]
	if asset == nil || len(asset.IPs) != 2 || len(asset.CNAMEs) != 1 || len(asset.ASN) != 1 {
		t.Fatalf("DNS enrichment not parsed: %+v", asset)
	}
}

func TestParseTlsx(t *testing.T) {
	path := writeTempFile(t, `{"host":"https://example.com:443","ip":"192.0.2.10","port":"443","tls_version":"tls13","cipher":"TLS_AES_128_GCM_SHA256","subject_cn":"example.com","issuer_cn":"Example CA","subject_an":["example.com"],"expired":false}`+"\n")
	rep := NewReport("example.com", "test")
	if err := ParseTlsx(path, rep); err != nil {
		t.Fatal(err)
	}
	asset := rep.Assets["example.com"]
	if asset == nil || len(asset.TLS) != 1 || asset.TLS[0].Version != "tls13" || asset.TLS[0].Port != 443 {
		t.Fatalf("TLS enrichment not parsed: %+v", asset)
	}
}

func TestParseJSVerify(t *testing.T) {
	content := `{"url":"https://example.com/app.js","kind":"dom-sink","pattern":"eval-call","severity":"high","payload":"alert(1)","verdict":"executed","evidence":"payload executed JavaScript (alert dialog with marker)"}
{"url":"https://example.com/app.js","kind":"dom-sink","pattern":"html-assignment","severity":"high","payload":"<img src=x>","verdict":"sink-reached","evidence":""}
{"url":"https://example.com/app.js","kind":"dom-sink","pattern":"location-assignment","severity":"medium","payload":"https://evil.example/","verdict":"not-observed","evidence":""}
`
	path := writeTempFile(t, content)

	rep := NewReport("example.com", "test")
	if err := ParseJSVerify(path, rep); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rep.JSVerified) != 2 {
		t.Fatalf("JSVerified = %d, want 2 (not-observed dropped): %+v", len(rep.JSVerified), rep.JSVerified)
	}
	if rep.JSVerified[0].Verdict != "executed" || rep.JSVerified[1].Verdict != "sink-reached" {
		t.Fatalf("unexpected verdicts: %+v", rep.JSVerified)
	}
	if rep.JSVerified[0].Payload != "alert(1)" {
		t.Fatalf("payload not carried: %+v", rep.JSVerified[0])
	}
}

func TestParseNmapCollection(t *testing.T) {
	dir := t.TempDir()
	xml := `<nmaprun><host><address addr="192.0.2.10" addrtype="ipv4"/><hostnames><hostname name="example.com"/></hostnames><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" version="1.25"/></port></ports></host></nmaprun>`
	if err := os.WriteFile(filepath.Join(dir, "host.xml"), []byte(xml), 0644); err != nil {
		t.Fatal(err)
	}
	rep := NewReport("example.com", "test")
	if err := ParseNmapCollection(dir, rep); err != nil {
		t.Fatal(err)
	}
	port := rep.Assets["example.com"].Ports[443]
	if port == nil || port.Service != "https" || port.Product != "nginx" {
		t.Fatalf("Nmap service not parsed: %+v", port)
	}
}

func TestParseWhatWebAndWAF(t *testing.T) {
	rep := NewReport("example.com", "test")
	if err := ParseWhatWeb(writeTempFile(t, "https://example.com [200 OK] HTTPServer[nginx], PHP[8.3]\n"), rep); err != nil {
		t.Fatal(err)
	}
	if err := ParseWAF(writeTempFile(t, "Checking https://example.com\nThe site https://example.com is behind Cloudflare WAF.\n"), rep); err != nil {
		t.Fatal(err)
	}
	asset := rep.Assets["example.com"]
	if asset == nil || len(asset.Technologies) == 0 || len(asset.WAFs) != 1 {
		t.Fatalf("web enrichment not parsed: %+v", asset)
	}
}

func TestStripANSI(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "plain string is unchanged", input: "plain text", want: "plain text"},
		{name: "reset code", input: "\x1b[0m", want: ""},
		{name: "red code", input: "\x1b[31m", want: ""},
		{name: "colored text", input: "\x1b[1;33mtext\x1b[0m", want: "text"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := stripANSI(tt.input); got != tt.want {
				t.Fatalf("stripANSI(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizeAssetNameStripsANSI(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "ansi reset after URL", input: "https://nakastream.tv\x1b[0m", want: "nakastream.tv"},
		{name: "ansi reset after host", input: "nakastream.tv\x1b[0m", want: "nakastream.tv"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeAssetName(tt.input); got != tt.want {
				t.Fatalf("normalizeAssetName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseWAFStripsANSI(t *testing.T) {
	rep := NewReport("example.com", "test")
	line := "The site https://example.com is behind \x1b[1;32mCloudflare\x1b[0m WAF."
	if err := ParseWAF(writeTempFile(t, line+"\n"), rep); err != nil {
		t.Fatal(err)
	}
	asset := rep.Assets["example.com"]
	if asset == nil || len(asset.WAFs) != 1 {
		t.Fatalf("WAF enrichment not parsed: %+v", asset)
	}
	if got := asset.WAFs[0]; got != "Cloudflare" {
		t.Fatalf("WAF = %q, want %q (no ANSI artifacts, not truncated)", got, "Cloudflare")
	}
}

func TestParseWhatWebStripsANSI(t *testing.T) {
	rep := NewReport("example.com", "test")
	line := "\x1b[32mhttps://example.com\x1b[0m [200 OK] HTTPServer[\x1b[1mnginx\x1b[0m], PHP[\x1b[33m8.3\x1b[0m]"
	if err := ParseWhatWeb(writeTempFile(t, line+"\n"), rep); err != nil {
		t.Fatal(err)
	}
	asset := rep.Assets["example.com"]
	if asset == nil || len(asset.Technologies) == 0 {
		t.Fatalf("web enrichment not parsed: %+v", asset)
	}
	for _, tech := range asset.Technologies {
		if strings.Contains(tech, "\x1b") || strings.Contains(tech, "[0m") {
			t.Fatalf("technology contains ANSI artifacts: %q", tech)
		}
	}
	for _, want := range []string{"HTTPServer", "PHP"} {
		if !contains(asset.Technologies, want) {
			t.Errorf("missing technology %q in %+v", want, asset.Technologies)
		}
	}
}

func contains(haystack []string, needle string) bool {
	for _, item := range haystack {
		if item == needle {
			return true
		}
	}
	return false
}

func TestParseFfuf(t *testing.T) {
	content := `{"results":[{"url":"https://example.com/admin","host":"example.com"}]}`
	path := writeTempFile(t, content)

	rep := NewReport("example.com", "test")
	err := ParseFfuf(path, rep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	asset := rep.GetOrCreateAsset("example.com")
	if len(asset.Paths) != 1 || asset.Paths[0] != "https://example.com/admin" {
		t.Error("failed to parse ffuf paths")
	}
}

func TestParseKatana(t *testing.T) {
	content := "https://example.com/login\nhttps://example.com/dashboard\n"
	path := writeTempFile(t, content)

	rep := NewReport("example.com", "test")
	err := ParseKatana(path, rep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	asset := rep.GetOrCreateAsset("example.com")
	if len(asset.Paths) != 2 {
		t.Error("failed to parse katana paths")
	}
}

func TestParseNuclei(t *testing.T) {
	content := `{"template-id":"cve-2021-1234","matched-at":"https://example.com","host":"https://example.com","info":{"name":"Test CVE","severity":"high","tags":["cve"],"reference":["https://example.test/advisory"],"classification":{"cve-id":["CVE-2021-1234"],"cwe-id":["CWE-79"]}}}`
	path := writeTempFile(t, content)

	rep := NewReport("example.com", "test")
	err := ParseNuclei(path, rep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	asset := rep.GetOrCreateAsset("example.com")
	if len(asset.Vulnerabilities) != 1 {
		t.Fatalf("expected 1 vuln, got %d", len(asset.Vulnerabilities))
	}

	v := asset.Vulnerabilities[0]
	if v.TemplateID != "cve-2021-1234" || v.Severity != "high" {
		t.Error("invalid nuclei vulnerability parsing")
	}
	if len(v.CVEs) != 1 || len(v.CWEs) != 1 || len(v.References) != 1 {
		t.Fatalf("missing nuclei metadata: %+v", v)
	}
}

func TestParseNucleiFiltersDedupsAndExtractsEvidence(t *testing.T) {
	content := `{"template-id":"tpl-1","matched-at":"https://example.com/x","host":"https://example.com","info":{"name":"Real","severity":"high","description":"Desc"}}
{"template-id":"tpl-1","matched-at":"https://example.com/x","host":"https://example.com","info":{"name":"Real","severity":"high"}}
{"template-id":"tpl-2","matched-at":"https://example.com/x","host":"https://example.com","matcher-status":false,"info":{"name":"NoMatch","severity":"info"}}
{"template-id":"tpl-3","matched-at":"https://example.com/y","host":"https://example.com","matcher-status":true,"extractor":["a=b","c=d"],"info":{"name":"Extracted","severity":"medium"}}
`
	path := writeTempFile(t, content)

	rep := NewReport("example.com", "test")
	if err := ParseNuclei(path, rep); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	asset := rep.GetOrCreateAsset("example.com")
	if len(asset.Vulnerabilities) != 2 {
		t.Fatalf("expected 2 vulns (dedup + no-match filtered), got %d", len(asset.Vulnerabilities))
	}

	var real, extracted *Vulnerability
	for _, v := range asset.Vulnerabilities {
		switch v.TemplateID {
		case "tpl-1":
			real = v
		case "tpl-3":
			extracted = v
		}
	}
	if real == nil || real.Description != "Desc" {
		t.Fatalf("bad deduplicated finding: %+v", real)
	}
	if extracted == nil || extracted.Evidence != "a=b; c=d" {
		t.Fatalf("bad extractor evidence: %+v", extracted)
	}
}

func TestParseJSSecrets(t *testing.T) {
	content := `{"url":"https://example.com/app.js","kind":"secret","pattern":"aws-access-key-id","severity":"critical","match":"AKIAIOSFODNN7EXAMPLE"}
{"url":"https://example.com/app.js","kind":"endpoint","pattern":"sensitive-api-endpoint","severity":"info","match":"/api/v1/admin/export"}
{"url":"https://example.com/app.js","kind":"cloud-storage","pattern":"aws-s3-bucket","severity":"medium","match":"uploads.s3.amazonaws.com"}
`
	path := writeTempFile(t, content)

	rep := NewReport("example.com", "test")
	if err := ParseJSSecrets(path, rep); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	asset := rep.GetOrCreateAsset("example.com")
	if len(asset.Vulnerabilities) != 2 {
		t.Fatalf("expected 2 vulnerabilities (secret + cloud-storage), got %d: %+v", len(asset.Vulnerabilities), asset.Vulnerabilities)
	}
	if len(asset.Paths) != 1 || asset.Paths[0] != "/api/v1/admin/export" {
		t.Fatalf("expected endpoint routed to Paths, got %+v", asset.Paths)
	}

	var secret, bucket *Vulnerability
	for _, v := range asset.Vulnerabilities {
		switch v.TemplateID {
		case "aws-access-key-id":
			secret = v
		case "aws-s3-bucket":
			bucket = v
		}
	}
	if secret == nil || secret.Evidence != "AKIAIOSFODNN7EXAMPLE" || secret.Severity != "critical" {
		t.Fatalf("bad secret vulnerability: %+v", secret)
	}
	if bucket == nil || bucket.Severity != "medium" || bucket.Title != "Cloud storage bucket referenced in JavaScript: aws-s3-bucket" {
		t.Fatalf("bad cloud-storage vulnerability: %+v", bucket)
	}
}

func TestParseJSDangerousPatternFindings(t *testing.T) {
	content := `{"url":"https://example.com/app.js","kind":"dom-sink","pattern":"eval-call","severity":"high","match":"eval(userInput)","line":42,"snippet":"eval(userInput)","payloads":["alert(document.domain)"]}
{"url":"https://example.com/app.js","kind":"proto-pollution","pattern":"proto-pollution-assignment","severity":"high","match":"obj.__proto__ = p","line":9,"snippet":"obj.__proto__ = p","payloads":["{\"__proto__\": {\"isAdmin\": true}}"]}
{"url":"https://example.com/app.js","kind":"postmessage","pattern":"message-listener-no-origin-check","severity":"medium","match":"addEventListener(\\\"message\\\", fn)","line":3,"snippet":"addEventListener(\\\"message\\\", fn)","payloads":[]}
`
	path := writeTempFile(t, content)

	rep := NewReport("example.com", "test")
	if err := ParseJSSecrets(path, rep); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	asset := rep.GetOrCreateAsset("example.com")
	if len(asset.Vulnerabilities) != 3 {
		t.Fatalf("expected 3 vulnerabilities, got %d: %+v", len(asset.Vulnerabilities), asset.Vulnerabilities)
	}

	wantTitles := map[string]string{
		"eval-call":                        "DOM XSS sink in JavaScript: eval-call",
		"proto-pollution-assignment":       "Prototype pollution vector in JavaScript: proto-pollution-assignment",
		"message-listener-no-origin-check": "Unvalidated postMessage usage in JavaScript: message-listener-no-origin-check",
	}
	byID := map[string]*Vulnerability{}
	for _, v := range asset.Vulnerabilities {
		byID[v.TemplateID] = v
	}
	for id, title := range wantTitles {
		v, ok := byID[id]
		if !ok {
			t.Fatalf("missing vulnerability %q in %+v", id, byID)
		}
		if v.Title != title {
			t.Errorf("title for %q = %q, want %q", id, v.Title, title)
		}
	}
	if ev := byID["eval-call"].Evidence; !strings.Contains(ev, "PoC payloads") || !strings.Contains(ev, "alert(document.domain)") {
		t.Fatalf("eval evidence should carry payloads, got %q", ev)
	}
	if ev := byID["message-listener-no-origin-check"].Evidence; strings.Contains(ev, "PoC payloads") {
		t.Fatalf("payload-less finding should not show a payload section, got %q", ev)
	}
}

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}
