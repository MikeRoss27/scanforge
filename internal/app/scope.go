package app

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/MikeRoss27/scanforge/internal/config"
	scanscope "github.com/MikeRoss27/scanforge/internal/scope"
	"golang.org/x/term"
)

const (
	scopeSourceExplicit   = "explicit-file"
	scopeSourceConfigured = "configured-file"
	scopeSourceImplicit   = "implicit"
	scopeModeFile         = "file"
)

// ScopeProposal is the exact authorization boundary shown before a run.
type ScopeProposal struct {
	Source  string
	Mode    string
	Input   string
	Note    string
	Entries []string
}

// ScopePrompter is injectable so confirmation behavior can be tested without a
// real terminal.
type ScopePrompter interface {
	IsTTY() bool
	Confirm(ScopeProposal) (bool, error)
}

type terminalScopePrompter struct {
	input  *os.File
	output io.Writer
}

func newTerminalScopePrompter() ScopePrompter {
	return &terminalScopePrompter{input: os.Stdin, output: os.Stderr}
}

func (p *terminalScopePrompter) IsTTY() bool {
	return p != nil && p.input != nil && term.IsTerminal(int(p.input.Fd()))
}

func (p *terminalScopePrompter) Confirm(proposal ScopeProposal) (bool, error) {
	if p == nil || p.input == nil {
		return false, fmt.Errorf("scope confirmation input is unavailable")
	}
	_, _ = fmt.Fprintf(p.output, "Effective scope (%s, mode %s):\n", proposal.Source, proposal.Mode)
	if proposal.Note != "" {
		_, _ = fmt.Fprintf(p.output, "Reason: %s\n", proposal.Note)
	}
	for _, entry := range proposal.Entries {
		_, _ = fmt.Fprintf(p.output, "  - %s\n", entry)
	}
	_, _ = fmt.Fprint(p.output, "Continue with this scope? [y/N] ")

	answer, err := bufio.NewReader(p.input).ReadString('\n')
	if err != nil && len(answer) == 0 {
		return false, fmt.Errorf("read scope confirmation: %w", err)
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "y" || answer == "yes", nil
}

type effectiveScope struct {
	value    *scanscope.Scope
	proposal ScopeProposal
}

func resolveScope(cfg *config.Config, target, explicitPath, modeValue string, additions, exclusions []string) (*effectiveScope, error) {
	forcesImplicit := modeValue != "" || len(additions) > 0 || len(exclusions) > 0
	fallbackNote := ""

	if explicitPath != "" {
		if forcesImplicit {
			return nil, fmt.Errorf("--scope cannot be combined with --scope-mode, --scope-add, or --exclude")
		}
		return loadFileScope(explicitPath, target, scopeSourceExplicit, true)
	}

	if !forcesImplicit && cfg.DefaultScope != "" {
		info, err := os.Stat(cfg.DefaultScope)
		switch {
		case err == nil && info.IsDir():
			return nil, fmt.Errorf("configured scope path %q is a directory", cfg.DefaultScope)
		case err == nil:
			resolved, loadErr := loadFileScope(cfg.DefaultScope, target, scopeSourceConfigured, false)
			if loadErr != nil {
				return nil, loadErr
			}
			if resolved != nil {
				return resolved, nil
			}
			fallbackNote = fmt.Sprintf("configured scope file %q does not allow the target", cfg.DefaultScope)
		case !os.IsNotExist(err):
			return nil, fmt.Errorf("unable to inspect configured scope file %q: %w", cfg.DefaultScope, err)
		default:
			fallbackNote = fmt.Sprintf("configured scope file %q was not found", cfg.DefaultScope)
		}
	} else if forcesImplicit {
		fallbackNote = "implicit scope requested by command-line options"
	}

	mode, err := parseScopeMode(modeValue)
	if err != nil {
		return nil, err
	}
	value, err := scanscope.FromTarget(target, mode, additions, exclusions)
	if err != nil {
		return nil, err
	}
	if !value.IsAllowed(target) {
		return nil, fmt.Errorf("target %q is excluded from the proposed implicit scope", target)
	}
	return &effectiveScope{
		value: value,
		proposal: ScopeProposal{
			Source:  scopeSourceImplicit,
			Mode:    string(mode),
			Input:   "generated from target",
			Note:    fallbackNote,
			Entries: value.Entries(),
		},
	}, nil
}

func loadFileScope(path, target, source string, strictTarget bool) (*effectiveScope, error) {
	value, err := scanscope.LoadFromFile(path)
	if err != nil {
		return nil, err
	}
	if !value.IsAllowed(target) {
		if strictTarget {
			return nil, fmt.Errorf("target %q is not allowed by explicit scope file %q", target, path)
		}
		return nil, nil
	}
	return &effectiveScope{
		value: value,
		proposal: ScopeProposal{
			Source:  source,
			Mode:    scopeModeFile,
			Input:   path,
			Entries: value.Entries(),
		},
	}, nil
}

func parseScopeMode(value string) (scanscope.Mode, error) {
	switch scanscope.Mode(strings.ToLower(strings.TrimSpace(value))) {
	case "", scanscope.ModeExact:
		return scanscope.ModeExact, nil
	case scanscope.ModeDomain:
		return scanscope.ModeDomain, nil
	default:
		return "", fmt.Errorf("invalid scope mode %q: expected exact or domain", value)
	}
}

func (a *App) confirmScope(proposal ScopeProposal, confirmed bool) error {
	if confirmed {
		return nil
	}
	if a.ScopePrompter == nil || !a.ScopePrompter.IsTTY() {
		return fmt.Errorf("scope confirmation required in non-interactive mode; review with 'scanforge plan' and pass --confirm-scope")
	}
	accepted, err := a.ScopePrompter.Confirm(proposal)
	if err != nil {
		return err
	}
	if !accepted {
		return fmt.Errorf("scope confirmation declined")
	}
	return nil
}
