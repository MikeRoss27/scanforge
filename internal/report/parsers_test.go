package report

import (
	"os"
	"path/filepath"
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

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}
