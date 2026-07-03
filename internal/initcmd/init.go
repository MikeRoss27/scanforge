package initcmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/MikeRoss27/scanforge/internal/config"
)

const scopeTemplate = `example.com
*.example.com
`

type Options struct {
	Force bool
}

type Result struct {
	Created []string
	Skipped []string
}

func Run(opts Options) (*Result, error) {
	result := &Result{}
	conflicts := make([]string, 0)

	files := map[string]string{
		config.DefaultConfigFile: config.Default().YAMLTemplate(),
		config.DefaultScope:      scopeTemplate,
	}

	for name, content := range files {
		path := filepath.Clean(name)
		if _, err := os.Stat(path); err == nil && !opts.Force {
			result.Skipped = append(result.Skipped, path)
			conflicts = append(conflicts, path)
			continue
		}

		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			return result, fmt.Errorf("unable to write %q: %w", path, err)
		}

		result.Created = append(result.Created, path)
	}

	runsDir := config.DefaultWorkspace
	if err := os.MkdirAll(runsDir, 0755); err != nil {
		return result, fmt.Errorf("unable to create workspace directory %q: %w", runsDir, err)
	}

	gitkeep := filepath.Join(runsDir, ".gitkeep")
	if _, err := os.Stat(gitkeep); os.IsNotExist(err) {
		if err := os.WriteFile(gitkeep, []byte(""), 0644); err != nil {
			return result, fmt.Errorf("unable to write %q: %w", gitkeep, err)
		}
		result.Created = append(result.Created, gitkeep)
	}

	if len(conflicts) > 0 {
		return result, fmt.Errorf("file(s) already exist: %v (use --force to overwrite)", conflicts)
	}

	return result, nil
}
