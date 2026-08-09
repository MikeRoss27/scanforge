// Package screenshot wraps httpx's built-in screenshot mode to capture
// visual snapshots of every alive URL for the engagement report.
package screenshot

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
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
		"-screenshot",
		"-screenshot-dir", screenshotDir,
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

// ScreenshotFiles returns the PNG snapshots captured in a screenshots dir,
// sorted by filename for determinism.
func ScreenshotFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if filepath.Ext(entry.Name()) != ".png" {
			continue
		}
		files = append(files, entry.Name())
	}
	return files, nil
}
