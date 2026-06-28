package nuclei

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFindingsJSON(t *testing.T) {
	dir := t.TempDir()

	input := filepath.Join(dir, "nuclei.jsonl")
	output := filepath.Join(dir, "findings.json")

	content := `{"template-id":"missing-csp","matched-at":"https://example.com","info":{"name":"Missing CSP Header","severity":"low"}}
{"template-id":"exposed-panel","host":"https://admin.example.com","info":{"name":"Exposed Admin Panel","severity":"medium"}}
invalid json
`

	if err := os.WriteFile(input, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	count, err := WriteFindingsJSON(input, output)
	if err != nil {
		t.Fatal(err)
	}

	if count != 2 {
		t.Fatalf("expected 2 findings, got %d", count)
	}

	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}

	var findings []Finding
	if err := json.Unmarshal(data, &findings); err != nil {
		t.Fatal(err)
	}

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings in file, got %d", len(findings))
	}

	if findings[0].TemplateID != "missing-csp" {
		t.Fatalf("unexpected first template id: %s", findings[0].TemplateID)
	}

	if findings[1].Severity != "medium" {
		t.Fatalf("unexpected second severity: %s", findings[1].Severity)
	}
}
