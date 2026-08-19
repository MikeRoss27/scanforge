package report

import (
	"bufio"
	"net"
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
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
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
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
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
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
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

// ParseWhatWeb parses the whatweb module's text output, extracting the
// target host and the bracketed technology names per line.
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

// ParseWAF parses the wafw00f module's text output, tracking the current
// host across lines and recording each detected WAF product.
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
