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
}

// Asset represents a single host or subdomain discovered during the scan.
type Asset struct {
	Name            string            `json:"name"`             // e.g., "sub.example.com"
	IPs             []string          `json:"ips,omitempty"`
	Ports           map[int]*Port     `json:"ports,omitempty"`  // Key is port number
	Technologies    []string          `json:"technologies,omitempty"`
	WAFs            []string          `json:"wafs,omitempty"`
	Vulnerabilities []*Vulnerability  `json:"vulnerabilities,omitempty"`
	Paths           []string          `json:"paths,omitempty"`
}

// Port represents an open port on an asset.
type Port struct {
	Number  int      `json:"number"`
	Service string   `json:"service,omitempty"` // e.g., "http", "ssh"
}

// Vulnerability represents a security finding.
type Vulnerability struct {
	Source     string `json:"source"`
	TemplateID string `json:"template_id"`
	Title      string `json:"title"`
	Severity   string `json:"severity"`
	MatchedAt  string `json:"matched_at"`
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
