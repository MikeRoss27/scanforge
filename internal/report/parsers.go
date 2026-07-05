package report

import (
	"bufio"
	"encoding/json"
	"net/url"
	"os"
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
	defer file.Close()

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
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		
		parts := strings.Split(line, ":")
		if len(parts) == 2 {
			host := parts[0]
			portStr := parts[1]
			portNum, err := strconv.Atoi(portStr)
			if err == nil {
				asset := report.GetOrCreateAsset(host)
				if _, ok := asset.Ports[portNum]; !ok {
					asset.Ports[portNum] = &Port{Number: portNum}
				}
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
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var record struct {
			URL   string   `json:"url"`
			Host  string   `json:"host"`
			Tech  []string `json:"tech"`
		}
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			continue
		}

		if record.Host != "" {
			asset := report.GetOrCreateAsset(record.Host)
			for _, t := range record.Tech {
				asset.Technologies = appendUnique(asset.Technologies, t)
			}
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
	defer file.Close()

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
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var record struct {
			TemplateID string `json:"template-id"`
			MatchedAt  string `json:"matched-at"`
			Host       string `json:"host"`
			Info       struct {
				Name     string `json:"name"`
				Severity string `json:"severity"`
			} `json:"info"`
		}
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			continue
		}

		host := record.Host
		if host == "" {
			if u, err := url.Parse(record.MatchedAt); err == nil {
				host = u.Hostname()
			} else {
				host = record.MatchedAt
			}
		}

		if host != "" {
			asset := report.GetOrCreateAsset(host)
			asset.Vulnerabilities = append(asset.Vulnerabilities, &Vulnerability{
				Source:     "nuclei",
				TemplateID: record.TemplateID,
				Title:      record.Info.Name,
				Severity:   record.Info.Severity,
				MatchedAt:  record.MatchedAt,
			})
		}
	}
	return scanner.Err()
}

func appendUnique(slice []string, val string) []string {
	for _, item := range slice {
		if item == val {
			return slice
		}
	}
	return append(slice, val)
}
