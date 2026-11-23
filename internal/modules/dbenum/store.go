package dbenum

import (
	"bufio"
	"encoding/json"
	"os"
)

// saveEnum writes the enumeration records as JSONL. An empty slice still
// creates (truncates) the file so the published artifact always exists.
func saveEnum(path string, recs []EnumRecord) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	for _, rec := range recs {
		if err := enc.Encode(rec); err != nil {
			return err
		}
	}
	return w.Flush()
}

// titleCase upper-cases the first rune of s (ASCII), for a display label. Kept
// local so we don't depend on the deprecated strings.Title.
func titleCase(s string) string {
	if s == "" {
		return s
	}
	b := []byte(s)
	if b[0] >= 'a' && b[0] <= 'z' {
		b[0] -= 'a' - 'A'
	}
	return string(b)
}
