// Package report machine-readable exports (SARIF 2.1.0, DefectDojo generic findings).
package report

import (
	"encoding/json"
	"os"
	"sort"
	"strings"

	"github.com/MikeRoss27/scanforge/internal/version"
)

// sarifSeverity maps a ScanForge severity onto a SARIF result level.
func sarifLevel(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

// sarifRules collects the distinct template IDs as SARIF rule descriptors.
func sarifRules(r *Report) map[string]sarifRule {
	rules := make(map[string]sarifRule)
	byID := make(map[string]*Vulnerability)
	for _, asset := range r.Assets {
		for _, v := range asset.Vulnerabilities {
			if v.TemplateID == "" {
				continue
			}
			if _, ok := rules[v.TemplateID]; ok {
				continue
			}
			rules[v.TemplateID] = sarifRule{
				ID:   v.TemplateID,
				Name: v.Title,
				ShortDescription: sarifText{
					Text: firstNonEmpty(v.Title, v.TemplateID),
				},
				FullDescription: sarifText{
					Text: firstNonEmpty(v.Description, v.Title, v.TemplateID),
				},
				DefaultConfiguration: sarifConfiguration{Level: sarifLevel(v.Severity)},
			}
			byID[v.TemplateID] = v
		}
	}
	return rules
}

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID                   string             `json:"id"`
	Name                 string             `json:"name,omitempty"`
	ShortDescription     sarifText          `json:"shortDescription,omitempty"`
	FullDescription      sarifText          `json:"fullDescription,omitempty"`
	DefaultConfiguration sarifConfiguration `json:"defaultConfiguration,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifConfiguration struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

// WriteSARIF writes the report as a SARIF 2.1.0 log consumable by GitHub
// code scanning, GitLab SAST and generic SARIF viewers.
func (r *Report) WriteSARIF(path string) error {
	rules := sarifRules(r)
	ruleList := make([]sarifRule, 0, len(rules))
	for _, rule := range rules {
		ruleList = append(ruleList, rule)
	}
	sort.Slice(ruleList, func(i, j int) bool { return ruleList[i].ID < ruleList[j].ID })

	var results []sarifResult
	for _, name := range sortedAssets(r) {
		for _, v := range r.Assets[name].Vulnerabilities {
			results = append(results, sarifResult{
				RuleID:  v.TemplateID,
				Level:   sarifLevel(v.Severity),
				Message: sarifText{Text: firstNonEmpty(v.Title, v.TemplateID)},
				Locations: []sarifLocation{{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{URI: v.MatchedAt},
					},
				}},
			})
		}
	}
	sort.Slice(results, func(i, j int) bool { return results[i].RuleID < results[j].RuleID })

	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:           "ScanForge",
					Version:        version.Version,
					InformationURI: "https://github.com/MikeRoss27/scanforge",
					Rules:          ruleList,
				},
			},
			Results: results,
		}},
	}
	return writeJSONFile(path, log)
}

// defectDojoSeverity maps a ScanForge severity onto DefectDojo's expected
// labels (Critical/High/Medium/Low/Info).
func defectDojoSeverity(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return "Critical"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "low":
		return "Low"
	default:
		return "Info"
	}
}

// defectDojoFinding is one entry of the DefectDojo "Generic Findings Import"
// format, importable with scan_type "Generic Findings Import".
type defectDojoFinding struct {
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	Description string   `json:"description,omitempty"`
	CWE         int      `json:"cwe,omitempty"`
	CVE         string   `json:"cve,omitempty"`
	CVSSv3      float64  `json:"cvssv3,omitempty"`
	References  string   `json:"references,omitempty"`
	Endpoint    string   `json:"endpoint,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

// cweNumber extracts the numeric id from "CWE-79" or "CWE-79.1".
func cweNumber(cwe string) int {
	value := strings.TrimPrefix(strings.TrimSpace(cwe), "CWE-")
	var n int
	for _, r := range value {
		if r < '0' || r > '9' {
			break
		}
		n = n*10 + int(r-'0')
	}
	return n
}

// WriteDefectDojo writes the report as a DefectDojo generic findings import
// (scan_type "Generic Findings Import"), so a run can be pushed to an
// existing DefectDojo instance or imported from the UI.
func (r *Report) WriteDefectDojo(path string) error {
	var findings []defectDojoFinding
	for _, name := range sortedAssets(r) {
		for _, v := range r.Assets[name].Vulnerabilities {
			var cve string
			if len(v.CVEs) > 0 {
				cve = v.CVEs[0]
			} else if strings.HasPrefix(v.TemplateID, "CVE-") {
				cve = v.TemplateID
			}
			var cwe int
			if len(v.CWEs) > 0 {
				cwe = cweNumber(v.CWEs[0])
			}
			finding := defectDojoFinding{
				Title:       v.Title,
				Severity:    defectDojoSeverity(v.Severity),
				Description: v.Description,
				CWE:         cwe,
				CVE:         cve,
				CVSSv3:      v.CVSS,
				References:  strings.Join(v.References, "\n"),
				Endpoint:    v.MatchedAt,
				Tags:        v.Tags,
			}
			if finding.Description == "" {
				finding.Description = v.Title
			}
			if finding.Endpoint == "" {
				finding.Endpoint = name
			}
			findings = append(findings, finding)
		}
	}
	return writeJSONFile(path, findings)
}

func writeJSONFile(path string, value interface{}) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0644)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
