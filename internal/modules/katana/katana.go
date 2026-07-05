package katana

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
		binary = "katana"
	}
	return &Module{binary: binary}
}

func (m *Module) Name() string { return "katana" }
func (m *Module) Description() string { return "A next-generation crawling and spidering framework" }
func (m *Module) Requires() []string { return []string{"alive_urls"} }
func (m *Module) Produces() []string { return []string{"crawled_urls"} }

func (m *Module) Run(ctx context.Context, runCtx *modules.RunContext, executor runner.Executor) (*modules.Result, error) {
	inputArt, err := runCtx.MustArtifact("alive_urls")
	if err != nil {
		return nil, err
	}
	inputFile := runCtx.Run.Path(inputArt.Path)

	outputFile := runCtx.Run.Path("05_content", "katana.txt")
	stderrFile := runCtx.Run.Path("00_meta", "katana.stderr.log")

	cmd := runner.Command{
		Name:       m.binary,
		Args:       []string{"-list", inputFile, "-silent", "-depth", "2"},
		Timeout:    45 * time.Minute,
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

	runCtx.AddArtifact("crawled_urls", modules.Artifact{
		Name: "crawled_urls",
		Type: "text",
		Path: "05_content/katana.txt",
	})

	status := "completed"
	if res.ExitCode != 0 {
		status = fmt.Sprintf("failed (exit code %d)", res.ExitCode)
	}

	return &modules.Result{
		Name:   m.Name(),
		Status: status,
		OutputFiles: map[string]string{
			"crawled_urls":  "05_content/katana.txt",
			"katana_stderr": "00_meta/katana.stderr.log",
		},
	}, nil
}
