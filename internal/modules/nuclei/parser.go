package nuclei

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
)

type nucleiRecord struct {
	TemplateID string `json:"template-id"`
	MatchedAt  string `json:"matched-at"`
	Host       string `json:"host"`
	Info       struct {
		Name     string `json:"name"`
		Severity string `json:"severity"`
	} `json:"info"`
}

type Finding struct {
	Source     string `json:"source"`
	Severity   string `json:"severity"`
	Target     string `json:"target"`
	Title      string `json:"title"`
	TemplateID string `json:"template_id"`
}

func WriteFindingsJSON(inputPath string, outputPath string) (int, error) {
	file, err := os.Open(inputPath)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	findings := make([]Finding, 0)

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024), 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var record nucleiRecord
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			continue
		}

		target := strings.TrimSpace(record.MatchedAt)
		if target == "" {
			target = strings.TrimSpace(record.Host)
		}

		title := strings.TrimSpace(record.Info.Name)
		if title == "" {
			title = strings.TrimSpace(record.TemplateID)
		}

		finding := Finding{
			Source:     "nuclei",
			Severity:   strings.TrimSpace(record.Info.Severity),
			Target:     target,
			Title:      title,
			TemplateID: strings.TrimSpace(record.TemplateID),
		}

		if finding.Target == "" && finding.TemplateID == "" {
			continue
		}

		findings = append(findings, finding)
	}

	if err := scanner.Err(); err != nil {
		return 0, err
	}

	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return 0, err
	}

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return 0, err
	}

	return len(findings), nil
}
