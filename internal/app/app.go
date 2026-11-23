// Package app wires configuration, scope validation, orchestration and
// reporting together behind the CLI commands.
package app

import (
	"fmt"

	"github.com/MikeRoss27/scanforge/internal/config"
	"github.com/MikeRoss27/scanforge/internal/console"
	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/storage"
	"github.com/MikeRoss27/scanforge/internal/workflows"
)

type App struct {
	ConfigPath    string
	ScopePrompter ScopePrompter
	Wizard        WizardPrompter
	WPPrompter    WPPrompter
}

func New(configPath string) *App {
	return &App{
		ConfigPath:    configPath,
		ScopePrompter: newTerminalScopePrompter(),
		Wizard:        newTerminalWizardPrompter(),
		WPPrompter:    newTerminalWPPrompter(),
	}
}

type RunOptions struct {
	Target      string
	TargetsFile string
	Profile     string
	// Workflow is the path of a YAML workflow replacing the profile
	// (--workflow). Mutually exclusive with Profile and WP.
	Workflow     string
	Scope        string
	ScopeMode    string
	ScopeAdd     []string
	Exclusions   []string
	ConfirmScope bool
	DryRun       bool
	// Verbosity is the structured output level: Quiet, Normal, Verbose
	// (-v), Debug (-vv) or Trace (-vvv). See console.Verbosity.
	Verbosity console.Verbosity

	// Proxy routes HTTP-capable modules through an intercepting proxy such
	// as Caido or Burp Suite (e.g. http://127.0.0.1:8080).
	Proxy string
	// Headers are applied to every outgoing HTTP request, for example to
	// carry an authenticated session (Cookie/Authorization).
	Headers []string
	// Nuclei carries nuclei-specific tuning (severity, tags, rate limiting).
	Nuclei modules.NucleiOptions
	// Ffuf carries ffuf-specific tuning (wordlist, status-code filtering).
	Ffuf modules.FfufOptions
	// NmapConcurrency bounds how many nmap processes run at once.
	NmapConcurrency int
	// WP adds the WordPress engagement chain to the selected profile
	// (--wp). The chain modules are no-ops on non-WordPress hosts.
	WP bool
	// WordPress carries WordPress-engagement tuning (enumeration mode,
	// aggressive wordlist, opt-in brute force).
	WordPress modules.WordPressOptions

	// compiled is the validated workflow, set by Run when Workflow is used.
	compiled *workflows.Compiled
}

type DoctorOptions struct {
	Profile string
	JSON    bool
	Verbose bool
}

type InitOptions struct {
	Force bool
}

// ExitCodeError carries a non-zero process exit code out of a command handler
// so the entry point can honor it without os.Exit in library code (which
// would skip defers and make the path untestable).
type ExitCodeError struct {
	Code int
}

func (e ExitCodeError) Error() string { return fmt.Sprintf("exit code %d", e.Code) }

func (a *App) loadConfig() (*config.Config, error) {
	return config.Load(config.ResolvePath(a.ConfigPath))
}

// Workspace resolves the configured runs root (default "runs/"), the same
// directory Run writes every scan into. Exported for callers outside this
// package that need to locate a run after the fact without re-running
// App.Run's whole config-loading path themselves — the benchmark command,
// in particular, which reads back the report a run it just triggered wrote.
func (a *App) Workspace() (string, error) {
	cfg, err := a.loadConfig()
	if err != nil {
		return "", err
	}
	return config.WorkspaceDir(cfg), nil
}

// runSession holds everything a single run needs after validation, so Run
// stays a thin sequence and each phase can be reasoned about and tested on
// its own.
type runSession struct {
	opts      RunOptions
	profile   string
	effective *effectiveScope
	// moduleNames is the final, already-adjusted module list (profile base
	// + --wp/--wp-bruteforce + the pre-scan WordPress suggestion, if
	// accepted) that execute() hands to the orchestrator. Resolving it here
	// instead of letting the orchestrator re-derive it from opts.Profile
	// alone is what makes any of those adjustments actually take effect.
	moduleNames []string
	scanRun     *storage.Run
	cfg         *config.Config
	reportErr   error
	// console owns every terminal write of the run and term describes the
	// output destination it renders for.
	console *console.Renderer
	term    console.Terminal
}
