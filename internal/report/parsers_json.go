package report

import (
	"bufio"
	"encoding/json"
	"net/url"
	"os"
	"strings"
)

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
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
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

// ParseFfuf parses the ffuf module's single-document JSON output.
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
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
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
			Host           string  `json:"host"`
			CVEID          string  `json:"cve_id"`
			Title          string  `json:"title"`
			Severity       string  `json:"severity"`
			CVSS           float64 `json:"cvss"`
			Reference      string  `json:"reference"`
			Note           string  `json:"note"`
			EPSS           float64 `json:"epss"`
			EPSSPercentile float64 `json:"epss_percentile"`
			KEV            bool    `json:"kev"`
		}
		if json.Unmarshal(line, &record) != nil || record.Host == "" || record.CVEID == "" {
			return
		}
		asset := report.GetOrCreateAsset(normalizeAssetName(record.Host))
		asset.Vulnerabilities = append(asset.Vulnerabilities, &Vulnerability{
			Source:         "techcve",
			TemplateID:     record.CVEID,
			Title:          record.Title,
			Severity:       record.Severity,
			CVSS:           record.CVSS,
			MatchedAt:      record.Host,
			Description:    record.Note,
			References:     []string{record.Reference},
			EPSS:           record.EPSS,
			EPSSPercentile: record.EPSSPercentile,
			KEV:            record.KEV,
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

// ParseDnsx parses the dnsx module's JSONL output (resolved hosts, IPs,
// CNAMEs, CDN and ASN metadata).
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

// ParseTlsx parses the tlsx module's JSONL output (TLS certificate details).
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

// ParseJSSecrets parses the jssecrets module's JSONL output: endpoint
// discoveries become asset paths, everything else becomes a finding.
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
