package nmap

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
		binary = "nmap"
	}
	return &Module{binary: binary}
}

func (m *Module) Name() string { return "nmap" }
func (m *Module) Description() string { return "Network exploration tool and security / port scanner" }
func (m *Module) Requires() []string { return nil } // Falls back to target
func (m *Module) Produces() []string { return []string{"nmap_xml"} }

func (m *Module) Run(ctx context.Context, runCtx *modules.RunContext, executor runner.Executor) (*modules.Result, error) {
	var inputArgs []string

	if inputArt, ok := runCtx.GetArtifact("open_ports"); ok {
		inputArgs = []string{"-iL", runCtx.Run.Path(inputArt.Path)}
	} else {
		inputArgs = []string{runCtx.Target}
	}

	xmlOutputFile := runCtx.Run.Path("03_ports", "nmap.xml")
	txtOutputFile := runCtx.Run.Path("03_ports", "nmap.txt")
	stderrFile := runCtx.Run.Path("00_meta", "nmap.stderr.log")

	args := append(inputArgs, "-oX", xmlOutputFile, "-oN", txtOutputFile, "-sV", "-T4")

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

	runCtx.AddArtifact("nmap_xml", modules.Artifact{
		Name: "nmap_xml",
		Type: "xml",
		Path: "03_ports/nmap.xml",
	})

	status := "completed"
	if res.ExitCode != 0 {
		status = fmt.Sprintf("failed (exit code %d)", res.ExitCode)
	}

	return &modules.Result{
		Name:   m.Name(),
		Status: status,
		OutputFiles: map[string]string{
			"nmap_xml":    "03_ports/nmap.xml",
			"nmap_txt":    "03_ports/nmap.txt",
			"nmap_stderr": "00_meta/nmap.stderr.log",
		},
	}, nil
}
