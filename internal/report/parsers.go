package report

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// ParseHosts parses a simple text file with one host/domain/URL per line.
func ParseHosts(path string, report *Report) error {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// If it's a URL, extract host
		host := line
		if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
			if u, err := url.Parse(line); err == nil {
				host = u.Hostname()
			}
		}

		report.GetOrCreateAsset(host)
	}
	return scanner.Err()
}

// ParsePorts parses host:port format (e.g., from naabu)
func ParsePorts(path string, report *Report) error {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		host, portStr, err := net.SplitHostPort(line)
		if err != nil {
			pos := strings.LastIndexByte(line, ':')
			if pos < 1 {
				continue
			}
			host, portStr = strings.Trim(line[:pos], "[]"), line[pos+1:]
		}
		portNum, err := strconv.Atoi(portStr)
		if err == nil && portNum > 0 && portNum <= 65535 {
			asset := report.GetOrCreateAsset(normalizeAssetName(host))
			if _, ok := asset.Ports[portNum]; !ok {
				asset.Ports[portNum] = &Port{Number: portNum}
			}
		}
	}
	return scanner.Err()
}

// ParseHttpx parses httpx JSONL output
func ParseHttpx(path string, report *Report) error {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var record struct {
			URL     string   `json:"url"`
			Host    string   `json:"host"`
			Input   string   `json:"input"`
			Tech    []string `json:"tech"`
			A       []string `json:"a"`
			AAAA    []string `json:"aaaa"`
			HostIP  string   `json:"host_ip"`
			CNAME   []string `json:"cname"`
			CDNName string   `json:"cdn_name"`
			ASN     *struct {
				Number  string `json:"as_number"`
				Name    string `json:"as_name"`
				Country string `json:"as_country"`
			} `json:"asn"`
			StatusCode    int             `json:"status_code"`
			Title         string          `json:"title"`
			WebServer     string          `json:"webserver"`
			ContentType   string          `json:"content_type"`
			ContentLength int64           `json:"content_length"`
			Location      string          `json:"location"`
			ResponseTime  string          `json:"time"`
			Favicon       json.RawMessage `json:"favicon"`
		}
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			continue
		}

		host := normalizeAssetName(record.Host)
		if host == "" {
			host = normalizeAssetName(record.URL)
		}
		if host == "" {
			host = normalizeAssetName(record.Input)
		}
		if host != "" {
			asset := report.GetOrCreateAsset(host)
			for _, t := range record.Tech {
				asset.Technologies = appendUnique(asset.Technologies, t)
			}
			for _, ip := range append(record.A, record.AAAA...) {
				asset.IPs = appendUnique(asset.IPs, ip)
			}
			if record.HostIP != "" {
				asset.IPs = appendUnique(asset.IPs, record.HostIP)
			}
			for _, cname := range record.CNAME {
				asset.CNAMEs = appendUnique(asset.CNAMEs, cname)
			}
			if record.CDNName != "" {
				asset.CDN = appendUnique(asset.CDN, record.CDNName)
			}
			if record.ASN != nil {
				value := strings.TrimSpace(strings.Join([]string{record.ASN.Number, record.ASN.Name, record.ASN.Country}, " "))
				asset.ASN = appendUnique(asset.ASN, value)
			}
			asset.HTTP = append(asset.HTTP, HTTPService{
				URL: record.URL, StatusCode: record.StatusCode, Title: record.Title,
				WebServer: record.WebServer, ContentType: record.ContentType,
				ContentLength: record.ContentLength, Location: record.Location,
				ResponseTime: record.ResponseTime, Favicon: rawString(record.Favicon),
			})
		}
	}
	return scanner.Err()
}

// ParseFfuf parses ffuf JSON output
func ParseFfuf(path string, report *Report) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var result struct {
		Results []struct {
			URL  string `json:"url"`
			Host string `json:"host"`
		} `json:"results"`
	}

	if err := json.Unmarshal(data, &result); err != nil {
		return err // Or skip
	}

	for _, res := range result.Results {
		host := res.Host
		if host == "" {
			if u, err := url.Parse(res.URL); err == nil {
				host = u.Hostname()
			}
		}
		if host != "" {
			asset := report.GetOrCreateAsset(host)
			asset.Paths = appendUnique(asset.Paths, res.URL)
		}
	}
	return nil
}

// ParseKatana parses Katana raw URLs
func ParseKatana(path string, report *Report) error {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if u, err := url.Parse(line); err == nil && u.Hostname() != "" {
			asset := report.GetOrCreateAsset(u.Hostname())
			asset.Paths = appendUnique(asset.Paths, line)
		}
	}
	return scanner.Err()
}

// ParseNuclei parses Nuclei JSONL output
func ParseNuclei(path string, report *Report) error {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	seen := make(map[string]struct{})
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var record struct {
			TemplateID    string   `json:"template-id"`
			MatchedAt     string   `json:"matched-at"`
			Host          string   `json:"host"`
			MatcherStatus *bool    `json:"matcher-status"`
			Extractor     []string `json:"extractor"`
			Info          struct {
				Name           string   `json:"name"`
				Severity       string   `json:"severity"`
				Description    string   `json:"description"`
				Tags           []string `json:"tags"`
				References     []string `json:"reference"`
				Classification struct {
					CVE []string `json:"cve-id"`
					CWE []string `json:"cwe-id"`
				} `json:"classification"`
			} `json:"info"`
		}
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			continue
		}

		// Matcher-status false records mean the template did not actually
		// match (e.g. multiple matchers with OR semantics); keep only true.
		if record.MatcherStatus != nil && !*record.MatcherStatus {
			continue
		}

		host := normalizeAssetName(record.Host)
		if host == "" {
			host = normalizeAssetName(record.MatchedAt)
		}
		if host == "" {
			continue
		}

		// The same template+host+path combination can fire repeatedly across
		// waves or retries; keep the first occurrence per combination.
		dedupKey := record.TemplateID + "|" + host + "|" + record.MatchedAt
		if _, ok := seen[dedupKey]; ok {
			continue
		}
		seen[dedupKey] = struct{}{}

		title := record.Info.Name
		if title == "" {
			title = record.TemplateID
		}

		asset := report.GetOrCreateAsset(host)
		asset.Vulnerabilities = append(asset.Vulnerabilities, &Vulnerability{
			Source:      "nuclei",
			TemplateID:  record.TemplateID,
			Title:       title,
			Description: record.Info.Description,
			Severity:    record.Info.Severity,
			MatchedAt:   record.MatchedAt,
			Evidence:    strings.Join(record.Extractor, "; "),
			Tags:        record.Info.Tags,
			CVEs:        record.Info.Classification.CVE,
			CWEs:        record.Info.Classification.CWE,
			References:  record.Info.References,
		})
	}
	return scanner.Err()
}

// ParseTechCVE parses the techcve module's version-based CVE findings.
func ParseTechCVE(path string, report *Report) error {
	return scanJSONLines(path, func(line []byte) {
		var record struct {
			Host      string `json:"host"`
			CVEID     string `json:"cve_id"`
			Title     string `json:"title"`
			Severity  string `json:"severity"`
			Reference string `json:"reference"`
			Note      string `json:"note"`
		}
		if json.Unmarshal(line, &record) != nil || record.Host == "" || record.CVEID == "" {
			return
		}
		asset := report.GetOrCreateAsset(normalizeAssetName(record.Host))
		asset.Vulnerabilities = append(asset.Vulnerabilities, &Vulnerability{
			Source:      "techcve",
			TemplateID:  record.CVEID,
			Title:       record.Title,
			Severity:    record.Severity,
			MatchedAt:   record.Host,
			Description: record.Note,
			References:  []string{record.Reference},
		})
	})
}

// ParseHTTPChecks parses the httpcheck module's hardening-gap findings.
func ParseHTTPChecks(path string, report *Report) error {
	return scanJSONLines(path, func(line []byte) {
		var record struct {
			URL      string `json:"url"`
			Check    string `json:"check"`
			Severity string `json:"severity"`
			Detail   string `json:"detail"`
		}
		if json.Unmarshal(line, &record) != nil || record.URL == "" || record.Check == "" {
			return
		}
		host := normalizeAssetName(record.URL)
		if host == "" {
			return
		}
		asset := report.GetOrCreateAsset(host)
		asset.Vulnerabilities = append(asset.Vulnerabilities, &Vulnerability{
			Source:      "httpcheck",
			TemplateID:  record.Check,
			Title:       httpCheckTitle(record.Check),
			Severity:    record.Severity,
			MatchedAt:   record.URL,
			Description: record.Detail,
		})
	})
}

// httpCheckTitle maps a check identifier to a human-readable title.
func httpCheckTitle(check string) string {
	titles := map[string]string{
		"missing-csp":                "Missing Content-Security-Policy header",
		"clickjacking-unprotected":   "Clickjacking not mitigated (no frame-ancestors/X-Frame-Options)",
		"missing-hsts":               "Missing Strict-Transport-Security header",
		"missing-x-frame-options":    "Missing X-Frame-Options header",
		"missing-nosniff":            "Missing X-Content-Type-Options: nosniff",
		"missing-referrer-policy":    "Missing Referrer-Policy header",
		"missing-permissions-policy": "Missing Permissions-Policy header",
		"cookie-without-secure":      "Cookie not marked Secure",
		"cookie-without-httponly":    "Cookie not marked HttpOnly",
	}
	if title, ok := titles[check]; ok {
		return title
	}
	return check
}

func ParseDnsx(path string, report *Report) error {
	return scanJSONLines(path, func(line []byte) {
		var record struct {
			Host    string   `json:"host"`
			A       []string `json:"a"`
			AAAA    []string `json:"aaaa"`
			CNAME   []string `json:"cname"`
			CDNName string   `json:"cdn-name"`
			ASN     *struct {
				Number  string `json:"as-number"`
				Name    string `json:"as-name"`
				Country string `json:"as-country"`
			} `json:"asn"`
		}
		if json.Unmarshal(line, &record) != nil || record.Host == "" {
			return
		}
		asset := report.GetOrCreateAsset(normalizeAssetName(record.Host))
		for _, ip := range append(record.A, record.AAAA...) {
			asset.IPs = appendUnique(asset.IPs, ip)
		}
		for _, cname := range record.CNAME {
			asset.CNAMEs = appendUnique(asset.CNAMEs, cname)
		}
		if record.CDNName != "" {
			asset.CDN = appendUnique(asset.CDN, record.CDNName)
		}
		if record.ASN != nil {
			value := strings.TrimSpace(strings.Join([]string{record.ASN.Number, record.ASN.Name, record.ASN.Country}, " "))
			asset.ASN = appendUnique(asset.ASN, value)
		}
	})
}

func ParseTlsx(path string, report *Report) error {
	return scanJSONLines(path, func(line []byte) {
		var record struct {
			Host       string          `json:"host"`
			IP         string          `json:"ip"`
			Port       json.RawMessage `json:"port"`
			Version    string          `json:"version"`
			TLSVersion string          `json:"tls_version"`
			Cipher     string          `json:"cipher"`
			CommonName string          `json:"subject_cn"`
			Issuer     string          `json:"issuer_cn"`
			SANs       []string        `json:"subject_an"`
			NotBefore  string          `json:"not_before"`
			NotAfter   string          `json:"not_after"`
			Expired    bool            `json:"expired"`
			SelfSigned bool            `json:"self_signed"`
		}
		if json.Unmarshal(line, &record) != nil {
			return
		}
		host := normalizeAssetName(record.Host)
		if host == "" {
			return
		}
		if record.Version == "" {
			record.Version = record.TLSVersion
		}
		asset := report.GetOrCreateAsset(host)
		if record.IP != "" {
			asset.IPs = appendUnique(asset.IPs, record.IP)
		}
		asset.TLS = append(asset.TLS, TLSService{
			Port: rawInt(record.Port), Version: record.Version, Cipher: record.Cipher,
			CommonName: record.CommonName, Issuer: record.Issuer, SANs: record.SANs,
			NotBefore: record.NotBefore, NotAfter: record.NotAfter,
			Expired: record.Expired, SelfSigned: record.SelfSigned,
		})
	})
}

func ParseJSSecrets(path string, report *Report) error {
	return scanJSONLines(path, func(line []byte) {
		var record struct {
			URL      string   `json:"url"`
			Kind     string   `json:"kind"`
			Pattern  string   `json:"pattern"`
			Severity string   `json:"severity"`
			Match    string   `json:"match"`
			Snippet  string   `json:"snippet"`
			Payloads []string `json:"payloads"`
		}
		if json.Unmarshal(line, &record) != nil || record.URL == "" {
			return
		}
		host := normalizeAssetName(record.URL)
		if host == "" {
			return
		}
		asset := report.GetOrCreateAsset(host)

		if record.Kind == "endpoint" {
			asset.Paths = appendUnique(asset.Paths, record.Match)
			return
		}

		evidence := record.Match
		if record.Snippet != "" {
			evidence = record.Snippet
		}
		if len(record.Payloads) > 0 {
			evidence += "\n\nPoC payloads:\n- " + strings.Join(record.Payloads, "\n- ")
		}
		asset.Vulnerabilities = append(asset.Vulnerabilities, &Vulnerability{
			Source:     "jssecrets",
			TemplateID: record.Pattern,
			Title:      jsFindingTitle(record.Kind, record.Pattern),
			Severity:   record.Severity,
			MatchedAt:  record.URL,
			Evidence:   evidence,
		})
	})
}

func jsFindingTitle(kind, pattern string) string {
	switch kind {
	case "cloud-storage":
		return "Cloud storage bucket referenced in JavaScript: " + pattern
	case "internal-host":
		return "Internal host/IP referenced in JavaScript"
	case "email":
		return "Email address exposed in JavaScript"
	case "source-map":
		return "Source map exposed (leaks original source code)"
	case "dom-sink":
		return "DOM XSS sink in JavaScript: " + pattern
	case "node-sink":
		return "Server-side Node.js API in JavaScript: " + pattern
	case "proto-pollution":
		return "Prototype pollution vector in JavaScript: " + pattern
	case "postmessage":
		return "Unvalidated postMessage usage in JavaScript: " + pattern
	case "env-leak":
		return "Environment variable access in JavaScript: " + pattern
	default:
		return "Exposed secret in JavaScript: " + pattern
	}
}

// ParseJSVerify loads the jsverify module's replay verdicts into the report.
// Only actionable outcomes (executed, sink-reached) are kept so the report
// highlights confirmed sinks rather than the full not-observed backlog.
func ParseJSVerify(path string, report *Report) error {
	return scanJSONLines(path, func(line []byte) {
		var record VerifiedFinding
		if json.Unmarshal(line, &record) != nil || record.URL == "" {
			return
		}
		if record.Verdict != "executed" && record.Verdict != "sink-reached" {
			return
		}
		report.JSVerified = append(report.JSVerified, record)
	})
}

func ParseNmapCollection(path string, report *Report) error {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var paths []string
	if info.IsDir() {
		err = filepath.WalkDir(path, func(candidate string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".xml") {
				paths = append(paths, candidate)
			}
			return nil
		})
	} else {
		paths = []string{path}
	}
	if err != nil {
		return err
	}
	for _, xmlPath := range paths {
		if err := parseNmapXML(xmlPath, report); err != nil {
			return err
		}
	}
	return nil
}

func parseNmapXML(path string, report *Report) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var result struct {
		Hosts []struct {
			Addresses []struct {
				Addr string `xml:"addr,attr"`
				Type string `xml:"addrtype,attr"`
			} `xml:"address"`
			Hostnames []struct {
				Name string `xml:"name,attr"`
			} `xml:"hostnames>hostname"`
			Ports []struct {
				ID       int    `xml:"portid,attr"`
				Protocol string `xml:"protocol,attr"`
				State    struct {
					Value string `xml:"state,attr"`
				} `xml:"state"`
				Service struct {
					Name    string `xml:"name,attr"`
					Product string `xml:"product,attr"`
					Version string `xml:"version,attr"`
				} `xml:"service"`
			} `xml:"ports>port"`
		} `xml:"host"`
	}
	if err := xml.Unmarshal(data, &result); err != nil {
		return err
	}
	for _, host := range result.Hosts {
		name := ""
		if len(host.Hostnames) > 0 {
			name = normalizeAssetName(host.Hostnames[0].Name)
		}
		for _, address := range host.Addresses {
			if name == "" && (address.Type == "ipv4" || address.Type == "ipv6") {
				name = address.Addr
			}
		}
		if name == "" {
			continue
		}
		asset := report.GetOrCreateAsset(name)
		for _, address := range host.Addresses {
			if address.Type == "ipv4" || address.Type == "ipv6" {
				asset.IPs = appendUnique(asset.IPs, address.Addr)
			}
		}
		for _, port := range host.Ports {
			if port.State.Value != "open" {
				continue
			}
			asset.Ports[port.ID] = &Port{
				Number: port.ID, Protocol: port.Protocol, Service: port.Service.Name,
				Product: port.Service.Product, Version: port.Service.Version,
			}
		}
	}
	return nil
}

var urlPattern = regexp.MustCompile(`https?://[^\s]+`)
var wafPattern = regexp.MustCompile(`(?i)is behind (?:a |an )?(.+?)(?: WAF)?(?:\.|$)`)

func ParseWhatWeb(path string, report *Report) error {
	return scanLines(path, func(line string) {
		rawURL := urlPattern.FindString(line)
		host := normalizeAssetName(rawURL)
		if host == "" {
			return
		}
		asset := report.GetOrCreateAsset(host)
		for _, field := range strings.Fields(line) {
			if pos := strings.IndexByte(field, '['); pos > 0 {
				asset.Technologies = appendUnique(asset.Technologies, strings.Trim(field[:pos], ","))
			}
		}
	})
}

func ParseWAF(path string, report *Report) error {
	currentHost := ""
	return scanLines(path, func(line string) {
		rawURL := urlPattern.FindString(line)
		if host := normalizeAssetName(rawURL); host != "" {
			currentHost = host
		}
		match := wafPattern.FindStringSubmatch(line)
		if currentHost != "" && len(match) == 2 {
			asset := report.GetOrCreateAsset(currentHost)
			asset.WAFs = appendUnique(asset.WAFs, strings.TrimSpace(match[1]))
		}
	})
}

func scanJSONLines(path string, consume func([]byte)) error {
	return scanLines(path, func(line string) { consume([]byte(line)) })
}

func scanLines(path string, consume func(string)) error {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer func() { _ = file.Close() }()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			consume(line)
		}
	}
	return scanner.Err()
}

func normalizeAssetName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if parsed, err := url.Parse(value); err == nil && parsed.Hostname() != "" {
		return strings.ToLower(parsed.Hostname())
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		return strings.ToLower(strings.Trim(host, "[]"))
	}
	return strings.ToLower(strings.Trim(strings.TrimSuffix(value, "."), "[]"))
}

func rawString(value json.RawMessage) string {
	if len(value) == 0 || string(value) == "null" {
		return ""
	}
	var text string
	if json.Unmarshal(value, &text) == nil {
		return text
	}
	var number json.Number
	if json.Unmarshal(value, &number) == nil {
		return number.String()
	}
	return fmt.Sprint(string(value))
}

func rawInt(value json.RawMessage) int {
	text := rawString(value)
	number, _ := strconv.Atoi(text)
	return number
}

func appendUnique(slice []string, val string) []string {
	for _, item := range slice {
		if item == val {
			return slice
		}
	}
	return append(slice, val)
}
