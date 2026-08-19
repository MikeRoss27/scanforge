// Package app wires configuration, scope validation, orchestration and
// reporting together behind the CLI commands.
package app

import (
	"fmt"

	"github.com/MikeRoss27/scanforge/internal/config"
	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

type App struct {
	ConfigPath    string
	ScopePrompter ScopePrompter
	Wizard        WizardPrompter
}

func New(configPath string) *App {
	return &App{
		ConfigPath:    configPath,
		ScopePrompter: newTerminalScopePrompter(),
		Wizard:        newTerminalWizardPrompter(),
	}
}

type RunOptions struct {
	Target       string
	TargetsFile  string
	Profile      string
	Scope        string
	ScopeMode    string
	ScopeAdd     []string
	Exclusions   []string
	ConfirmScope bool
	DryRun       bool
	Verbose      bool

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

// runSession holds everything a single run needs after validation, so Run
// stays a thin sequence and each phase can be reasoned about and tested on
// its own.
type runSession struct {
	opts      RunOptions
	profile   string
	effective *effectiveScope
	scanRun   *storage.Run
	cfg       *config.Config
	reportErr error
}
