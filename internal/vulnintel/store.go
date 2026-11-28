// Package vulnintel maintains a local, file-based vulnerability intelligence
// cache (NVD CVE API 2.0, CISA KEV, FIRST EPSS) and answers product/version
// queries from it.
//
// Network access happens only through an explicit Client run (the
// `scanforge intel update` command). Loading and matching never touch the
// network, so scans stay offline-safe.
package vulnintel

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Source names.
const (
	SourceNVD  = "nvd"
	SourceKEV  = "kev"
	SourceEPSS = "epss"
)

// AllSources lists every supported feed in update order.
var AllSources = []string{SourceNVD, SourceKEV, SourceEPSS}

// EnvDir overrides the cache directory.
const EnvDir = "SCANFORGE_INTEL_DIR"

// Provenance is stored on every record so each datum can be traced back to
// the feed and moment it came from.
type Provenance struct {
	Source      string    `json:"source"`
	FetchedAt   time.Time `json:"fetched_at"`
	FeedVersion string    `json:"feed_version,omitempty"`
}

// CPEMatch is one vulnerable CPE applicability statement of a CVE.
type CPEMatch struct {
	Criteria  string `json:"criteria"`
	Vendor    string `json:"vendor"`
	Product   string `json:"product"`
	Version   string `json:"version,omitempty"` // CPE version field; "*" or "-" when unspecified
	StartIncl string `json:"start_incl,omitempty"`
	StartExcl string `json:"start_excl,omitempty"`
	EndIncl   string `json:"end_incl,omitempty"`
	EndExcl   string `json:"end_excl,omitempty"`
}

// CVERecord is the normalized NVD record.
type CVERecord struct {
	ID           string     `json:"id"`
	Description  string     `json:"description,omitempty"`
	Severity     string     `json:"severity,omitempty"`
	CVSS         float64    `json:"cvss,omitempty"`
	Published    string     `json:"published,omitempty"`
	LastModified string     `json:"last_modified,omitempty"`
	Matches      []CPEMatch `json:"matches,omitempty"`
	Provenance
}

// KEVRecord is one CISA Known Exploited Vulnerabilities entry.
type KEVRecord struct {
	CVEID      string `json:"cve_id"`
	Vendor     string `json:"vendor,omitempty"`
	Product    string `json:"product,omitempty"`
	Name       string `json:"name,omitempty"`
	DateAdded  string `json:"date_added,omitempty"`
	DueDate    string `json:"due_date,omitempty"`
	Ransomware string `json:"ransomware,omitempty"`
	Provenance
}

// EPSSRecord is one FIRST EPSS score.
type EPSSRecord struct {
	CVEID      string  `json:"cve_id"`
	Score      float64 `json:"epss"`
	Percentile float64 `json:"percentile"`
	ScoreDate  string  `json:"score_date,omitempty"`
	Provenance
}

// SourceMeta summarizes the last successful update of one source.
type SourceMeta struct {
	Source      string    `json:"source"`
	FetchedAt   time.Time `json:"fetched_at"`
	FeedVersion string    `json:"feed_version,omitempty"`
	Records     int       `json:"records"`
}

// Meta is the content of meta.json.
type Meta struct {
	Sources map[string]SourceMeta `json:"sources"`
}

// SortedSources returns source names present in meta, sorted.
func (m Meta) SortedSources() []string {
	names := make([]string, 0, len(m.Sources))
	for n := range m.Sources {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Store is a directory of JSONL files, one per source, plus meta.json.
type Store struct {
	Dir string
}

// DefaultDir returns $SCANFORGE_INTEL_DIR or <user cache>/scanforge/vulnintel.
func DefaultDir() (string, error) {
	if dir := os.Getenv(EnvDir); dir != "" {
		return dir, nil
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("cannot resolve cache directory: %w", err)
	}
	return filepath.Join(cache, "scanforge", "vulnintel"), nil
}

// OpenDefault returns a Store on the default directory.
func OpenDefault() (*Store, error) {
	dir, err := DefaultDir()
	if err != nil {
		return nil, err
	}
	return &Store{Dir: dir}, nil
}

func (s *Store) file(source string) string { return filepath.Join(s.Dir, source+".jsonl") }
func (s *Store) metaFile() string          { return filepath.Join(s.Dir, "meta.json") }

// ReadMeta returns the stored metadata; a missing cache yields empty Meta.
func (s *Store) ReadMeta() (Meta, error) {
	meta := Meta{Sources: map[string]SourceMeta{}}
	data, err := os.ReadFile(s.metaFile())
	if errors.Is(err, os.ErrNotExist) {
		return meta, nil
	}
	if err != nil {
		return meta, fmt.Errorf("failed to read intel metadata: %w", err)
	}
	if err := json.Unmarshal(data, &meta); err != nil {
		return meta, fmt.Errorf("failed to parse intel metadata: %w", err)
	}
	if meta.Sources == nil {
		meta.Sources = map[string]SourceMeta{}
	}
	return meta, nil
}

// HasData reports whether at least one source has been fetched.
func (s *Store) HasData() bool {
	meta, err := s.ReadMeta()
	return err == nil && len(meta.Sources) > 0
}

// replace atomically writes records as JSONL and updates meta.json.
func replace[T any](s *Store, sm *SourceMeta, records []T) error {
	if err := os.MkdirAll(s.Dir, 0o755); err != nil {
		return fmt.Errorf("failed to create intel directory: %w", err)
	}
	tmp, err := os.CreateTemp(s.Dir, sm.Source+"-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	w := bufio.NewWriter(tmp)
	enc := json.NewEncoder(w)
	for i := range records {
		if err := enc.Encode(records[i]); err != nil {
			_ = tmp.Close()
			return fmt.Errorf("failed to write %s records: %w", sm.Source, err)
		}
	}
	if err := w.Flush(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), s.file(sm.Source)); err != nil {
		return fmt.Errorf("failed to replace %s cache: %w", sm.Source, err)
	}

	meta, err := s.ReadMeta()
	if err != nil {
		return err
	}
	sm.Records = len(records)
	meta.Sources[sm.Source] = *sm
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(s.metaFile(), data, 0o644); err != nil {
		return fmt.Errorf("failed to write intel metadata: %w", err)
	}
	return nil
}

// readAll streams a source file; a missing file is not an error. A single
// malformed line (partial write, truncated download, bit rot) is skipped
// rather than failing the whole read: epssFor's line index already treats
// the EPSS cache this way, and Load/OpenIfPresent otherwise turn one bad
// line anywhere in an ~86 MB NVD/KEV feed into a silent, total loss of CVE
// correlation for the run (OpenIfPresent swallows Load's error and returns
// nil, so techcve/wpcve run with zero intel and no warning).
func readAll[T any](s *Store, source string, fn func(T)) error {
	f, err := os.Open(s.file(source))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var rec T
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			continue
		}
		fn(rec)
	}
	return sc.Err()
}
