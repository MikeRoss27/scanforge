package ffuf

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
)

type Module struct {
	binary string
}

func New(binary string) *Module {
	if binary == "" {
		binary = "ffuf"
	}
	return &Module{binary: binary}
}

func (m *Module) Name() string { return "ffuf" }
func (m *Module) Description() string { return "Fast web fuzzer written in Go" }
func (m *Module) Requires() []string { return []string{"alive_urls"} }
func (m *Module) Produces() []string { return []string{"discovered_paths"} }

func (m *Module) Run(ctx context.Context, runCtx *modules.RunContext, executor runner.Executor) (*modules.Result, error) {
	inputArt, err := runCtx.MustArtifact("alive_urls")
	if err != nil {
		return nil, err
	}
	inputFile := runCtx.Run.Path(inputArt.Path)

	wordlist := "/usr/share/wordlists/dirb/common.txt"
	if !runCtx.DryRun {
		if _, err := os.Stat(wordlist); os.IsNotExist(err) {
			return nil, fmt.Errorf("default wordlist not found: %s", wordlist)
		}
	}

	outputFile := runCtx.Run.Path("05_content", "ffuf.json")
	stderrFile := runCtx.Run.Path("00_meta", "ffuf.stderr.log")

	// Use ffuf's multiple wordlist syntax to iterate over urls and paths
	args := []string{
		"-w", fmt.Sprintf("%s:URL", inputFile),
		"-w", fmt.Sprintf("%s:FUZZ", wordlist),
		"-u", "URL/FUZZ",
		"-o", outputFile,
		"-of", "json",
		"-mc", "200,301,302,403",
	}

	cmd := runner.Command{
		Name:       m.binary,
		Args:       args,
		Timeout:    1 * time.Hour,
		StderrFile: stderrFile,
	}

	if err := runner.AppendCommandLog(runCtx.Run.CommandsLog, cmd); err != nil {
		return nil, fmt.Errorf("failed to write commands log: %w", err)
	}

	res, err := executor.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to run command %q: %w", cmd.Name, err)
	}

	runCtx.AddArtifact("discovered_paths", modules.Artifact{
		Name: "discovered_paths",
		Type: "json",
		Path: "05_content/ffuf.json",
	})

	status := "completed"
	if res.ExitCode != 0 {
		status = fmt.Sprintf("failed (exit code %d)", res.ExitCode)
	}

	return &modules.Result{
		Name:   m.Name(),
		Status: status,
		OutputFiles: map[string]string{
			"discovered_paths": "05_content/ffuf.json",
			"ffuf_stderr":      "00_meta/ffuf.stderr.log",
		},
	}, nil
}
