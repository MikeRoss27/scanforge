package report

import (
	"encoding/json"
	"fmt"
	"os"
)

// LoadFromFile reads a previously written report.json back into a Report.
// Unlike the diff command's reconsolidation from raw artifacts, this trusts
// the file as-is — callers that need the authoritative, artifact-derived
// report should reconsolidate instead (see internal/app.Diff).
func LoadFromFile(path string) (*Report, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read report %q: %w", path, err)
	}
	var rep Report
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, fmt.Errorf("failed to parse report %q: %w", path, err)
	}
	return &rep, nil
}
