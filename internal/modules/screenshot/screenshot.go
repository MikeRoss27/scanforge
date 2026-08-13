// Package screenshot wraps httpx's built-in screenshot mode to capture
// visual snapshots of every alive URL for the engagement report.
package screenshot

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
)

const outputDir = "04_web/screenshots"

// Module reuses the httpx binary (its -screenshot mode) and therefore needs
// no dedicated tool installation.
type Module struct {
	binary string
}

func New(binary string) *Module {
	if binary == "" {
		binary = "httpx"
	}
	return &Module{binary: binary}
}

func (m *Module) Name() string { return "screenshot" }

func (m *Module) Description() string {
	return "Captures visual snapshots of alive URLs with httpx"
}

func (m *Module) Requires() []string { return []string{"alive_urls"} }

func (m *Module) Produces() []string { return []string{"screenshots"} }

func (m *Module) Run(ctx context.Context, runCtx *modules.RunContext, executor runner.Executor) (*modules.Result, error) {
	inputArt, err := runCtx.MustArtifact("alive_urls")
	if err != nil {
		return nil, err
	}
	inputFile := runCtx.Run.Path(inputArt.Path)
	screenshotDir := runCtx.Run.Path(outputDir)
	stderrFile := runCtx.Run.Path("00_meta", "screenshot.stderr.log")

	args := []string{
		"-l", inputFile,
		"-silent",
		"-ss",
		"-srd", screenshotDir,
		"-timeout", "15",
		"-retries", "1",
	}
	args = append(args, runCtx.ProxyArgs("-proxy")...)
	args = append(args, runCtx.HeaderArgs("-H")...)

	cmd := runner.Command{
		Name:       m.binary,
		Args:       args,
		Timeout:    15 * time.Minute,
		StdoutFile: runCtx.Run.Path("00_meta", "screenshot.stdout.log"),
		StderrFile: stderrFile,
	}

	if err := runner.AppendCommandLog(runCtx.Run.CommandsLog, cmd); err != nil {
		return nil, fmt.Errorf("failed to write commands log: %w", err)
	}

	res, err := executor.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to run command %q: %w", cmd.Name, err)
	}

	if !runCtx.DryRun {
		if _, err := os.Stat(screenshotDir); os.IsNotExist(err) {
			if err := os.MkdirAll(screenshotDir, 0755); err != nil {
				return nil, err
			}
		}
	}

	if err := runCtx.AddArtifact("screenshots", modules.Artifact{
		Name: "screenshots",
		Type: "dir",
		Path: outputDir,
	}); err != nil {
		return nil, fmt.Errorf("failed to publish screenshots: %w", err)
	}

	status := "completed"
	if res.ExitCode != 0 {
		status = fmt.Sprintf("failed (exit code %d)", res.ExitCode)
	}

	return &modules.Result{
		Name:   m.Name(),
		Status: status,
		OutputFiles: map[string]string{
			"screenshots":       outputDir,
			"screenshot_stderr": "00_meta/screenshot.stderr.log",
		},
	}, nil
}

// ScreenshotFiles returns the PNG snapshots captured under a screenshots dir,
// walking subdirectories because httpx (-srd) writes them as
// <dir>/screenshot/<host>/<hash>.png. Sorted by filename for determinism.
func ScreenshotFiles(dir string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if filepath.Ext(entry.Name()) != ".png" {
			return nil
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	sort.Strings(files)
	return files, nil
}
