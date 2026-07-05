package whatweb

import (
	"context"
	"fmt"
	"time"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
)

type Module struct {
	binary string
}

func New(binary string) *Module {
	if binary == "" {
		binary = "whatweb"
	}
	return &Module{binary: binary}
}

func (m *Module) Name() string { return "whatweb" }
func (m *Module) Description() string { return "Next generation web scanner" }
func (m *Module) Requires() []string { return []string{"alive_urls"} }
func (m *Module) Produces() []string { return []string{"technologies_raw"} }

func (m *Module) Run(ctx context.Context, runCtx *modules.RunContext, executor runner.Executor) (*modules.Result, error) {
	inputArt, err := runCtx.MustArtifact("alive_urls")
	if err != nil {
		return nil, err
	}
	inputFile := runCtx.Run.Path(inputArt.Path)

	outputFile := runCtx.Run.Path("04_web", "whatweb.txt")
	stderrFile := runCtx.Run.Path("00_meta", "whatweb.stderr.log")

	cmd := runner.Command{
		Name:       m.binary,
		Args:       []string{"-i", inputFile, "--color=never"},
		Timeout:    20 * time.Minute,
		StdoutFile: outputFile,
		StderrFile: stderrFile,
	}

	if err := runner.AppendCommandLog(runCtx.Run.CommandsLog, cmd); err != nil {
		return nil, fmt.Errorf("failed to write commands log: %w", err)
	}

	res, err := executor.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to run command %q: %w", cmd.Name, err)
	}

	runCtx.AddArtifact("technologies_raw", modules.Artifact{
		Name: "technologies_raw",
		Type: "text",
		Path: "04_web/whatweb.txt",
	})

	status := "completed"
	if res.ExitCode != 0 {
		status = fmt.Sprintf("failed (exit code %d)", res.ExitCode)
	}

	return &modules.Result{
		Name:   m.Name(),
		Status: status,
		OutputFiles: map[string]string{
			"whatweb_raw":    "04_web/whatweb.txt",
			"whatweb_stderr": "00_meta/whatweb.stderr.log",
		},
	}, nil
}
