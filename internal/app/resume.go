package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/MikeRoss27/scanforge/internal/config"
	"github.com/MikeRoss27/scanforge/internal/console"
	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
	scanscope "github.com/MikeRoss27/scanforge/internal/scope"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

// ResumeOptions selects the run to resume. Proxy and Headers are not stored
// in the manifest (they may be secrets): pass them again to resume an
// authenticated run, otherwise the modules' input hashes change and they are
// re-executed.
type ResumeOptions struct {
	// Run is a run ID, "<target>/<id>" or a run directory path.
	Run       string
	Verbosity console.Verbosity
	Proxy     string
	Headers   []string
}

// persistedOptions is the non-secret subset of RunOptions stored in the
// manifest so a run can be rebuilt identically.
type persistedOptions struct {
	Nuclei          modules.NucleiOptions    `json:"nuclei"`
	Ffuf            modules.FfufOptions      `json:"ffuf"`
	NmapConcurrency int                      `json:"nmap_concurrency,omitempty"`
	WordPress       modules.WordPressOptions `json:"wordpress"`
	Incremental     bool                     `json:"incremental,omitempty"`
}

func persistParams(opts RunOptions, moduleNames []string) (*storage.RunParams, error) {
	raw, err := json.Marshal(persistedOptions{
		Nuclei:          opts.Nuclei,
		Ffuf:            opts.Ffuf,
		NmapConcurrency: opts.NmapConcurrency,
		WordPress:       opts.WordPress,
		Incremental:     opts.Incremental,
	})
	if err != nil {
		return nil, fmt.Errorf("encode run parameters: %w", err)
	}
	return &storage.RunParams{Modules: append([]string(nil), moduleNames...), Options: raw}, nil
}

func fileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// Resume reloads a previous run and executes only what is not already
// checkpointed: modules completed with an unchanged input hash and intact
// outputs are reused, everything else (pending, running, failed, cancelled,
// skipped, or invalidated) runs again. The stored effective scope is reused
// verbatim and can never be widened by resuming.
func (a *App) Resume(ctx context.Context, opts ResumeOptions) error {
	cfg, err := a.loadConfig()
	if err != nil {
		return err
	}
	run, err := storage.FindRun(config.WorkspaceDir(cfg), opts.Run)
	if err != nil {
		return err
	}
	session, err := a.prepareResume(cfg, run, opts)
	if err != nil {
		return err
	}
	return session.executeAndFinish(ctx)
}

func (a *App) prepareResume(cfg *config.Config, run *storage.Run, opts ResumeOptions) (*runSession, error) {
	m := run.Manifest
	if m.ScopeSHA256 == "" {
		return nil, fmt.Errorf("run %s predates checkpoints (no scope digest recorded): it cannot be resumed safely, start a new run", run.ID)
	}
	scopeRel := m.ScopePath
	if scopeRel == "" {
		scopeRel = "00_meta/effective-scope.txt"
	}
	scopePath := run.Path(scopeRel)
	digest, err := fileSHA256(scopePath)
	if err != nil {
		return nil, fmt.Errorf("read stored effective scope: %w", err)
	}
	if digest != m.ScopeSHA256 {
		return nil, fmt.Errorf("effective scope %s was modified since the run was created: refusing to resume", scopePath)
	}
	value, err := scanscope.LoadFromFile(scopePath)
	if err != nil {
		return nil, fmt.Errorf("load stored effective scope: %w", err)
	}
	effective := &effectiveScope{
		value: value,
		proposal: ScopeProposal{
			Source:  m.ScopeSource,
			Mode:    m.ScopeMode,
			Input:   scopePath,
			Entries: value.Entries(),
		},
	}

	profile := m.Profile
	if profile == "" {
		profile = cfg.DefaultProfile
	}
	var moduleNames []string
	var persisted persistedOptions
	if m.Params != nil {
		moduleNames = append(moduleNames, m.Params.Modules...)
		if len(m.Params.Options) > 0 {
			if err := json.Unmarshal(m.Params.Options, &persisted); err != nil {
				return nil, fmt.Errorf("decode stored run parameters: %w", err)
			}
		}
	}
	if len(moduleNames) == 0 {
		moduleNames, err = cfg.ProfileModules(profile)
		if err != nil {
			return nil, err
		}
	}

	runOpts := RunOptions{
		Target:          m.Target,
		Profile:         profile,
		DryRun:          m.DryRun,
		Verbosity:       opts.Verbosity,
		Proxy:           opts.Proxy,
		Headers:         opts.Headers,
		Nuclei:          persisted.Nuclei,
		Ffuf:            persisted.Ffuf,
		NmapConcurrency: persisted.NmapConcurrency,
		WordPress:       persisted.WordPress,
		Incremental:     persisted.Incremental,
	}

	m2 := &run.Manifest
	m2.Status = "running"
	m2.CompletedAt = ""
	m2.ResumeCount++
	if err := run.WriteManifest(); err != nil {
		return nil, fmt.Errorf("update manifest: %w", err)
	}

	session := newRunSession(runOpts, profile, effective, moduleNames, run, cfg)
	session.resume = true
	session.printIntro(len(moduleNames))
	session.console.Info("resuming run %s (resume #%d)", run.ID, m2.ResumeCount)
	return session, nil
}

// RunStatus returns a human-readable report on one run's checkpoints.
func (a *App) RunStatus(ref string) (*storage.Run, string, error) {
	cfg, err := a.loadConfig()
	if err != nil {
		return nil, "", err
	}
	run, err := storage.FindRun(config.WorkspaceDir(cfg), ref)
	if err != nil {
		return nil, "", err
	}
	return run, FormatRunStatus(run), nil
}

// FormatRunStatus renders run state and per-module checkpoints.
func FormatRunStatus(run *storage.Run) string {
	m := run.Manifest
	var b strings.Builder
	fmt.Fprintf(&b, "Run:       %s\n", run.ID)
	fmt.Fprintf(&b, "Target:    %s\n", m.Target)
	fmt.Fprintf(&b, "Profile:   %s\n", m.Profile)
	fmt.Fprintf(&b, "Status:    %s\n", m.Status)
	fmt.Fprintf(&b, "Started:   %s\n", m.StartedAt)
	if m.CompletedAt != "" {
		fmt.Fprintf(&b, "Completed: %s\n", m.CompletedAt)
	}
	if m.ResumeCount > 0 {
		fmt.Fprintf(&b, "Resumes:   %d\n", m.ResumeCount)
	}
	fmt.Fprintf(&b, "Dir:       %s\n\n", run.RootDir)

	counts := map[string]int{}
	for _, rec := range m.Modules {
		counts[rec.Status]++
		line := fmt.Sprintf("  %-14s %-10s", rec.Name, rec.Status)
		if rec.InputHash != "" {
			line += " " + rec.InputHash[:12]
		}
		if rec.Reason != "" {
			line += "  (" + rec.Reason + ")"
		}
		if rec.Error != "" {
			line += "  error: " + firstLine(rec.Error)
		}
		b.WriteString(line + "\n")
	}
	if len(m.Modules) == 0 {
		b.WriteString("  no module checkpoints recorded\n")
	}
	if remaining := len(m.Modules) - counts[storage.ModuleCompleted]; m.Status != "completed" && remaining > 0 {
		fmt.Fprintf(&b, "\nResumable: yes (%d module(s) to run) -> scanforge resume %s\n", remaining, run.ID)
	}
	return b.String()
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// ListRuns returns the runs under the configured workspace, newest first,
// optionally restricted to one target.
func (a *App) ListRuns(target string) ([]*storage.Run, error) {
	cfg, err := a.loadConfig()
	if err != nil {
		return nil, err
	}
	runs, err := storage.ListRuns(config.WorkspaceDir(cfg))
	if err != nil {
		return nil, err
	}
	if target == "" {
		return runs, nil
	}
	var filtered []*storage.Run
	for _, run := range runs {
		if run.Target == target {
			filtered = append(filtered, run)
		}
	}
	return filtered, nil
}

// FormatRunList renders runs as an aligned table.
func FormatRunList(runs []*storage.Run) string {
	if len(runs) == 0 {
		return "no runs found\n"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%-22s %-28s %-10s %-9s %s\n", "RUN ID", "TARGET", "STATUS", "MODULES", "PROFILE")
	for _, run := range runs {
		done := 0
		for _, rec := range run.Manifest.Modules {
			if rec.Status == storage.ModuleCompleted {
				done++
			}
		}
		fmt.Fprintf(&b, "%-22s %-28s %-10s %-9s %s\n",
			run.ID, run.Target, run.Manifest.Status,
			fmt.Sprintf("%d/%d", done, len(run.Manifest.Modules)), run.Manifest.Profile)
	}
	return b.String()
}

// toolVersionArgs lists the flag that prints each external tool's version.
var toolVersionArgs = map[string][]string{
	"subfinder": {"-version"}, "dnsx": {"-version"}, "httpx": {"-version"},
	"naabu": {"-version"}, "katana": {"-version"}, "nuclei": {"-version"},
	"tlsx": {"-version"}, "ffuf": {"-V"}, "gau": {"--version"},
	"nmap": {"--version"}, "whatweb": {"--version"}, "wafw00f": {"--version"},
}

// detectToolVersions best-effort queries the version of every selected
// module's external tool through the injected executor (never os/exec). A
// missing tool or unsupported flag simply yields no version.
func detectToolVersions(ctx context.Context, executor runner.Executor, cfg *config.Config, moduleNames []string) map[string]string {
	versions := make(map[string]string, len(moduleNames))
	dir, err := os.MkdirTemp("", "scanforge-versions-")
	if err != nil {
		return versions
	}
	defer func() { _ = os.RemoveAll(dir) }()
	for _, name := range moduleNames {
		args, ok := toolVersionArgs[name]
		if !ok {
			continue
		}
		out := filepath.Join(dir, name+".out")
		errFile := filepath.Join(dir, name+".err")
		cmd := runner.Command{
			Name:       cfg.ToolPath(name),
			Args:       args,
			StdoutFile: out,
			StderrFile: errFile,
			Timeout:    10 * time.Second,
		}
		if _, err := executor.Run(ctx, cmd); err != nil {
			continue
		}
		stdout, _ := os.ReadFile(out)
		stderr, _ := os.ReadFile(errFile)
		versions[name] = strings.TrimSpace(string(stdout) + "\n" + string(stderr))
	}
	return versions
}
