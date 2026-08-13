package app

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/MikeRoss27/scanforge/internal/profile"
	"github.com/MikeRoss27/scanforge/internal/ui"
	"golang.org/x/term"
)

// WizardPrompter collects the pieces of a run the user did not provide
// (target, profile) so bare "scanforge run" becomes a guided setup instead of
// a plain "target is required" error. It is injectable so the interactive
// behavior can be tested without a terminal, mirroring ScopePrompter.
type WizardPrompter interface {
	IsTTY() bool
	AskTarget() (string, error)
	AskProfile(available []string, current string) (string, error)
}

type terminalWizardPrompter struct {
	input   *os.File
	output  io.Writer
	introed bool
}

func newTerminalWizardPrompter() WizardPrompter {
	return &terminalWizardPrompter{input: os.Stdin, output: os.Stderr}
}

func (p *terminalWizardPrompter) IsTTY() bool {
	return p != nil && p.input != nil && term.IsTerminal(int(p.input.Fd()))
}

// intro prints the setup panel once, before the first question.
func (p *terminalWizardPrompter) intro() {
	if p.introed {
		return
	}
	p.introed = true
	_, _ = fmt.Fprintln(p.output)
	_, _ = fmt.Fprintln(p.output, ui.PanelWith("✨ INTERACTIVE SETUP",
		"Press Enter to accept the suggested value.", ui.Accent, ui.Accent))
	_, _ = fmt.Fprintln(p.output)
}

func (p *terminalWizardPrompter) AskTarget() (string, error) {
	if p == nil || p.input == nil {
		return "", fmt.Errorf("interactive input is unavailable")
	}
	p.intro()
	reader := bufio.NewReader(p.input)
	for {
		_, _ = fmt.Fprintf(p.output, "  %s %s ", ui.DimBold("TARGET"), ui.Primary(">"))
		answer, err := reader.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("read target: %w", err)
		}
		if answer = strings.TrimSpace(answer); answer != "" {
			return answer, nil
		}
		_, _ = fmt.Fprintln(p.output, ui.Yellow("  Target cannot be empty."))
	}
}

func (p *terminalWizardPrompter) AskProfile(available []string, current string) (string, error) {
	if p == nil || p.input == nil {
		return "", fmt.Errorf("interactive input is unavailable")
	}
	p.intro()
	if len(available) == 0 {
		available = profile.Names()
	}
	reader := bufio.NewReader(p.input)
	for {
		_, _ = fmt.Fprintln(p.output, ui.DimBold("  PROFILE"))
		defaultIdx := 0
		for i, name := range available {
			label := fmt.Sprintf("    %2d) %s", i+1, name)
			if name == current {
				label += ui.Dim("   (default)")
				defaultIdx = i + 1
			}
			_, _ = fmt.Fprintln(p.output, label)
		}
		prompt := fmt.Sprintf("  CHOOSE [%d]: ", defaultIdx)
		if defaultIdx == 0 {
			prompt = fmt.Sprintf("  CHOOSE [1-%d]: ", len(available))
		}
		_, _ = fmt.Fprint(p.output, ui.DimBold(prompt))

		answer, err := reader.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("read profile: %w", err)
		}
		answer = strings.TrimSpace(answer)
		if answer == "" && current != "" {
			return current, nil
		}
		if idx, err := strconv.Atoi(answer); err == nil && idx >= 1 && idx <= len(available) {
			return available[idx-1], nil
		}
		_, _ = fmt.Fprintln(p.output, ui.Yellow("  Invalid choice."))
	}
}

// applyWizard fills the pieces of a run the user did not provide, asking
// interactively when stdin is a terminal. Outside a TTY the options are left
// untouched so the plain non-interactive errors still fire.
func (a *App) applyWizard(opts RunOptions) (RunOptions, error) {
	if a.Wizard == nil || !a.Wizard.IsTTY() {
		return opts, nil
	}
	if opts.Target == "" && opts.TargetsFile == "" {
		target, err := a.Wizard.AskTarget()
		if err != nil {
			return opts, err
		}
		opts.Target = target
	}
	if opts.Profile == "" {
		current := ""
		if cfg, err := a.loadConfig(); err == nil {
			current = cfg.DefaultProfile
		}
		profileName, err := a.Wizard.AskProfile(profile.Names(), current)
		if err != nil {
			return opts, err
		}
		opts.Profile = profileName
	}
	return opts, nil
}
