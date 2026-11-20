// Package wpcore holds the shared WordPress fingerprint record and helpers
// used by the wp* modules: wpdetect writes it, the downstream modules read
// it. Keeping the schema in one place guarantees the writers and readers
// cannot drift apart.
package wpcore

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
)

const OutputDir = "04_wordpress"

// FingerprintRecord is one line of wp-fingerprint.jsonl, produced by
// wpdetect. Even non-WordPress hosts are recorded so every probed host is
// covered and downstream modules can trust the artifact end to end.
type FingerprintRecord struct {
	Target      string   `json:"target"`
	IsWordPress bool     `json:"is_wordpress"`
	CoreVersion string   `json:"core_version,omitempty"`
	Sources     []string `json:"sources"`
	Confidence  string   `json:"confidence"`
	FetchedAt   string   `json:"fetched_at"`
}

// LoadFingerprint reads wp-fingerprint.jsonl and returns the hosts that
// identified as WordPress.
func LoadFingerprint(path string) ([]FingerprintRecord, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = file.Close() }()

	var items []FingerprintRecord
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var item FingerprintRecord
		if err := json.Unmarshal([]byte(line), &item); err != nil {
			continue
		}
		if item.IsWordPress {
			items = append(items, item)
		}
	}
	return items, scanner.Err()
}
