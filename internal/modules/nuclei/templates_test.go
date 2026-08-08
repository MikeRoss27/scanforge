package nuclei

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type templateDoc struct {
	ID   string `yaml:"id"`
	Info struct {
		Name        string `yaml:"name"`
		Author      string `yaml:"author"`
		Severity    string `yaml:"severity"`
		Description string `yaml:"description"`
		Tags        string `yaml:"tags"`
	} `yaml:"info"`
	HTTP []struct {
		Method string   `yaml:"method"`
		Path   []string `yaml:"path"`
		Raw    []string `yaml:"raw"`
	} `yaml:"http"`
}

func TestBundledTemplatesValid(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "templates")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read templates dir: %v", err)
	}

	var found []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		found = append(found, filepath.Join(dir, e.Name()))
	}

	if len(found) < 3 {
		t.Fatalf("expected at least 3 bundled templates, got %d", len(found))
	}

	for _, path := range found {
		t.Run(path, func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read template: %v", err)
			}

			var doc templateDoc
			if err := yaml.Unmarshal(data, &doc); err != nil {
				t.Fatalf("parse template yaml: %v", err)
			}

			if !strings.HasPrefix(doc.ID, "scanforge-") {
				t.Errorf("template id %q should use the scanforge- prefix", doc.ID)
			}
			if doc.Info.Name == "" || doc.Info.Severity == "" || doc.Info.Description == "" {
				t.Errorf("template %q must declare info.name, info.severity and info.description", doc.ID)
			}
			if len(doc.HTTP) == 0 {
				t.Errorf("template %q must define an http request block", doc.ID)
			}
			for _, req := range doc.HTTP {
				if len(req.Path) == 0 && len(req.Raw) == 0 {
					t.Errorf("template %q http request has no path or raw block", doc.ID)
				}
			}
		})
	}
}
