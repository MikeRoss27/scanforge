package report

import (
	"time"
)

// Report represents the final aggregated results of a scan run.
type Report struct {
	Target      string            `json:"target"`
	Profile     string            `json:"profile"`
	StartedAt   time.Time         `json:"started_at"`
	CompletedAt time.Time         `json:"completed_at"`
	Status      string            `json:"status"`
	Assets      map[string]*Asset `json:"assets"` // Key is the host/subdomain
	// JSVerified holds the jsverify module's replay verdicts, one entry per
	// attempted PoC payload (executed / sink-reached / not-observed).
	JSVerified []VerifiedFinding `json:"js_verified,omitempty"`
	// Screenshots lists the captured snapshots, paths relative to
	// 04_web/screenshots/ (httpx -srd nests them per host).
	Screenshots []string `json:"screenshots,omitempty"`
}

// VerifiedFinding is the outcome of replaying one jssecrets PoC payload in a
// headless browser.
type VerifiedFinding struct {
	URL      string `json:"url"`
	Page     string `json:"page"`
	Kind     string `json:"kind"`
	Pattern  string `json:"pattern"`
	Severity string `json:"severity"`
	Payload  string `json:"payload"`
	Verdict  string `json:"verdict"`
	Evidence string `json:"evidence,omitempty"`
}

// Asset represents a single host or subdomain discovered during the scan.
type Asset struct {
	Name            string           `json:"name"`
	IPs             []string         `json:"ips,omitempty"`
	CNAMEs          []string         `json:"cnames,omitempty"`
	ASN             []string         `json:"asn,omitempty"`
	CDN             []string         `json:"cdn,omitempty"`
	Ports           map[int]*Port    `json:"ports,omitempty"`
	HTTP            []HTTPService    `json:"http,omitempty"`
	TLS             []TLSService     `json:"tls,omitempty"`
	Technologies    []string         `json:"technologies,omitempty"`
	WAFs            []string         `json:"wafs,omitempty"`
	Vulnerabilities []*Vulnerability `json:"vulnerabilities,omitempty"`
	Paths           []string         `json:"paths,omitempty"`
}

type Port struct {
	Number   int    `json:"number"`
	Protocol string `json:"protocol,omitempty"`
	Service  string `json:"service,omitempty"`
	Product  string `json:"product,omitempty"`
	Version  string `json:"version,omitempty"`
}

type HTTPService struct {
	URL           string `json:"url"`
	StatusCode    int    `json:"status_code,omitempty"`
	Title         string `json:"title,omitempty"`
	WebServer     string `json:"web_server,omitempty"`
	ContentType   string `json:"content_type,omitempty"`
	ContentLength int64  `json:"content_length,omitempty"`
	Location      string `json:"location,omitempty"`
	ResponseTime  string `json:"response_time,omitempty"`
	Favicon       string `json:"favicon,omitempty"`
}

type TLSService struct {
	Port       int      `json:"port,omitempty"`
	Version    string   `json:"version,omitempty"`
	Cipher     string   `json:"cipher,omitempty"`
	CommonName string   `json:"common_name,omitempty"`
	Issuer     string   `json:"issuer,omitempty"`
	SANs       []string `json:"sans,omitempty"`
	NotBefore  string   `json:"not_before,omitempty"`
	NotAfter   string   `json:"not_after,omitempty"`
	Expired    bool     `json:"expired,omitempty"`
	SelfSigned bool     `json:"self_signed,omitempty"`
}

// Vulnerability represents a security finding.
type Vulnerability struct {
	Source         string   `json:"source"`
	TemplateID     string   `json:"template_id"`
	Title          string   `json:"title"`
	Description    string   `json:"description,omitempty"`
	Severity       string   `json:"severity"`
	MatchedAt      string   `json:"matched_at"`
	Evidence       string   `json:"evidence,omitempty"`
	Tags           []string `json:"tags,omitempty"`
	CVEs           []string `json:"cves,omitempty"`
	CWEs           []string `json:"cwes,omitempty"`
	References     []string `json:"references,omitempty"`
	CVSS           float64  `json:"cvss,omitempty"`
	EPSS           float64  `json:"epss,omitempty"`
	EPSSPercentile float64  `json:"epss_percentile,omitempty"`
	KEV            bool     `json:"kev,omitempty"`
}

func NewReport(target, profile string) *Report {
	return &Report{
		Target:  target,
		Profile: profile,
		Assets:  make(map[string]*Asset),
	}
}

// GetOrCreateAsset returns the existing asset or creates a new one.
func (r *Report) GetOrCreateAsset(name string) *Asset {
	if asset, ok := r.Assets[name]; ok {
		return asset
	}
	asset := &Asset{
		Name:  name,
		Ports: make(map[int]*Port),
	}
	r.Assets[name] = asset
	return asset
}
