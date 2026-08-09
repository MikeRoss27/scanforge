// Package dnsbrute wraps the shuffledns tool for DNS bruteforcing.
package dnsbrute

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
)

// defaultWordlistCandidates are searched in order when no wordlist is
// configured, so an out-of-the-box run works on common distro layouts.
var defaultWordlistCandidates = []string{
	"/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
	"/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
	"/usr/share/seclists/Discovery/DNS/namelist.txt",
	"/opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt",
	"/usr/share/wordlists/amass/subdomains.lst",
}

type Module struct {
	binary string
}

func New(binary string) *Module {
	if binary == "" {
		binary = "shuffledns"
	}
	return &Module{binary: binary}
}

func (m *Module) Name() string        { return "dnsbrute" }
func (m *Module) Description() string { return "DNS bruteforce with shuffledns and massdns" }
func (m *Module) Requires() []string  { return []string{"subdomains"} }
func (m *Module) Produces() []string  { return []string{"brute_subdomains"} }

func (m *Module) Run(ctx context.Context, runCtx *modules.RunContext, executor runner.Executor) (*modules.Result, error) {
	inputArt, err := runCtx.MustArtifact("subdomains")
	if err != nil {
		return nil, err
	}
	inputFile := runCtx.Run.Path(inputArt.Path)

	wordlist := resolveWordlist()
	if !runCtx.DryRun {
		if wordlist == "" {
			return nil, fmt.Errorf("no DNS wordlist found (checked: %s); install SecLists (e.g. 'sudo apt install seclists')", strings.Join(defaultWordlistCandidates, ", "))
		}
		if _, err := os.Stat(wordlist); os.IsNotExist(err) {
			return nil, fmt.Errorf("wordlist not found: %s", wordlist)
		}
	} else if wordlist == "" {
		wordlist = "<wordlist: none found>"
	}

	outputFile := runCtx.Run.Path("01_subdomains", "brute.txt")
	stderrFile := runCtx.Run.Path("00_meta", "dnsbrute.stderr.log")

	cmd := runner.Command{
		Name:       m.binary,
		Args:       []string{"-d", inputFile, "-w", wordlist, "-silent"},
		Timeout:    10 * time.Minute,
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

	if err := runCtx.AddArtifact("brute_subdomains", modules.Artifact{
		Name: "brute_subdomains",
		Type: "text",
		Path: "01_subdomains/brute.txt",
	}); err != nil {
		return nil, fmt.Errorf("failed to publish bruteforce results: %w", err)
	}

	status := "completed"
	if res.ExitCode != 0 {
		status = fmt.Sprintf("failed (exit code %d)", res.ExitCode)
	}

	return &modules.Result{
		Name:   m.Name(),
		Status: status,
		OutputFiles: map[string]string{
			"brute_subdomains": "01_subdomains/brute.txt",
			"dnsbrute_stderr":  "00_meta/dnsbrute.stderr.log",
		},
	}, nil
}

func resolveWordlist() string {
	for _, candidate := range defaultWordlistCandidates {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	return ""
}
