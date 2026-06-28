package httpx

import (
	"bufio"
	"encoding/json"
	"os"
	"sort"
	"strings"
)

type httpxRecord struct {
	URL string `json:"url"`
}

func WriteAliveURLs(inputPath string, outputPath string) (int, error) {
	file, err := os.Open(inputPath)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	seen := make(map[string]struct{})

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024), 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var record httpxRecord
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			continue
		}

		url := strings.TrimSpace(record.URL)
		if url == "" {
			continue
		}

		seen[url] = struct{}{}
	}

	if err := scanner.Err(); err != nil {
		return 0, err
	}

	urls := make([]string, 0, len(seen))
	for url := range seen {
		urls = append(urls, url)
	}

	sort.Strings(urls)

	content := strings.Join(urls, "\n")
	if len(urls) > 0 {
		content += "\n"
	}

	if err := os.WriteFile(outputPath, []byte(content), 0644); err != nil {
		return 0, err
	}

	return len(urls), nil
}
