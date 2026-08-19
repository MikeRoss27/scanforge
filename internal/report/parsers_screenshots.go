package report

import (
	"os"
	"path/filepath"
	"sort"
)

// ParseScreenshots records the PNG snapshots captured by the screenshot
// module. path is the screenshots directory; filenames are stored as-is so
// report.md can list them relative to the run root.
func ParseScreenshots(path string, report *Report) error {
	var files []string
	err := filepath.WalkDir(path, func(p string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if filepath.Ext(entry.Name()) != ".png" {
			return nil
		}
		rel, relErr := filepath.Rel(path, p)
		if relErr != nil {
			return relErr
		}
		files = append(files, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	sort.Strings(files)
	report.Screenshots = append(report.Screenshots, files...)
	return nil
}
