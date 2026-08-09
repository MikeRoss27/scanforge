// Package ffuf wraps the ffuf directory and file fuzzing tool.
package ffuf

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
)

// defaultWordlistCandidates are searched in order when no wordlist is
// configured, so an out-of-the-box run works on common distro layouts.
var defaultWordlistCandidates = []string{
	"/usr/share/wordlists/dirb/common.txt",
	"/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
	"/usr/share/seclists/Discovery/Web-Content/common.txt",
	"/opt/SecLists/Discovery/Web-Content/common.txt",
	"~/tools/dirb-common.txt",
}

type Module struct {
	binary string
}

func New(binary string) *Module {
	if binary == "" {
		binary = "ffuf"
	}
	return &Module{binary: binary}
}

func (m *Module) Name() string        { return "ffuf" }
func (m *Module) Description() string { return "Fast web fuzzer written in Go" }
func (m *Module) Requires() []string  { return []string{"alive_urls"} }
func (m *Module) Produces() []string  { return []string{"discovered_paths"} }

func (m *Module) Run(ctx context.Context, runCtx *modules.RunContext, executor runner.Executor) (*modules.Result, error) {
	inputArt, err := runCtx.MustArtifact("alive_urls")
	if err != nil {
		return nil, err
	}
	inputFile := runCtx.Run.Path(inputArt.Path)

	opts := runCtx.Ffuf
	wordlist := resolveWordlist(opts.Wordlist)
	if !runCtx.DryRun {
		if wordlist == "" {
			return nil, fmt.Errorf("no ffuf wordlist found (checked: %s); install wordlists (e.g. 'sudo apt install wordlists') or pass --ffuf-wordlist <path>", strings.Join(defaultWordlistCandidates, ", "))
		}
		if _, err := os.Stat(wordlist); os.IsNotExist(err) {
			return nil, fmt.Errorf("wordlist not found: %s", wordlist)
		}
	} else if wordlist == "" {
		// Dry runs log the command even when no wordlist is installed; keep
		// the placeholder obvious instead of emitting an invalid "-w :FUZZ".
		wordlist = "<wordlist: none found>"
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
	if opts.FilterCodes != "" {
		args = append(args, "-fc", opts.FilterCodes)
	}
	args = append(args, runCtx.ProxyArgs("-x")...)
	args = append(args, runCtx.HeaderArgs("-H")...)

	cmd := runner.Command{
		Name:       m.binary,
		Args:       args,
		Timeout:    1 * time.Hour,
		StdoutFile: runCtx.Run.Path("00_meta", "ffuf.stdout.log"),
		StderrFile: stderrFile,
	}

	if err := runner.AppendCommandLog(runCtx.Run.CommandsLog, cmd); err != nil {
		return nil, fmt.Errorf("failed to write commands log: %w", err)
	}

	res, err := executor.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to run command %q: %w", cmd.Name, err)
	}

	if err := runCtx.AddArtifact("discovered_paths", modules.Artifact{
		Name: "discovered_paths",
		Type: "json",
		Path: "05_content/ffuf.json",
	}); err != nil {
		return nil, fmt.Errorf("failed to publish discovered paths: %w", err)
	}

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

// resolveWordlist returns the configured wordlist (with ~ expanded) or, when
// none is set, the first default candidate that exists on disk.
func resolveWordlist(configured string) string {
	if configured != "" {
		return expandPath(configured)
	}
	for _, candidate := range defaultWordlistCandidates {
		path := expandPath(candidate)
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

// expandPath resolves a leading ~ to the current user's home directory.
func expandPath(path string) string {
	if path == "~" || strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(path, "~"))
		}
	}
	return path
}
