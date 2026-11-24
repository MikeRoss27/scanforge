// Package nuclei wraps the nuclei vulnerability scanner.
package nuclei

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
)

type Module struct {
	binary string
}

func New(binary string) *Module {
	if binary == "" {
		binary = "nuclei"
	}
	return &Module{binary: binary}
}

func (m *Module) Name() string {
	return "nuclei"
}

func (m *Module) Description() string {
	return "Fast and customizable vulnerability scanner"
}

func (m *Module) Requires() []string {
	return []string{"attack_surface_urls"}
}

func (m *Module) Produces() []string {
	return []string{"nuclei_raw"}
}

// SoftRequires waits for wafw00f to finish, when it's part of the profile,
// so WAF detection (GetWAFInfo) is settled before the scan starts.
func (m *Module) SoftRequires() []string { return []string{"waf_raw"} }

func (m *Module) Run(ctx context.Context, runCtx *modules.RunContext, executor runner.Executor) (*modules.Result, error) {
	inputArt, focus, err := runCtx.FocusedInput("attack_surface_urls")
	if err != nil {
		return nil, err
	}
	inputFile := runCtx.Run.Path(inputArt.Path)

	if focus.Empty() {
		// Incremental run with nothing new or changed: publish an empty
		// result instead of launching a scan without targets.
		if err := os.WriteFile(runCtx.Run.Path("06_vulns", "nuclei.jsonl"), nil, 0o644); err != nil {
			return nil, fmt.Errorf("failed to write empty nuclei results: %w", err)
		}
		if err := runCtx.AddArtifact("nuclei_raw", modules.Artifact{
			Name: "nuclei_raw", Type: "jsonl", Path: "06_vulns/nuclei.jsonl",
		}); err != nil {
			return nil, fmt.Errorf("failed to publish nuclei results: %w", err)
		}
		return &modules.Result{
			Name: m.Name(), Status: "skipped", Reason: focus.SkipReason(),
			OutputFiles: map[string]string{"nuclei_raw": "06_vulns/nuclei.jsonl"},
		}, nil
	}

	opts := runCtx.Nuclei
	if opts.UpdateTemplates {
		updateCmd := runner.Command{
			Name:       m.binary,
			Args:       []string{"-update-templates"},
			Timeout:    10 * time.Minute,
			StdoutFile: runCtx.Run.Path("00_meta", "nuclei-update.stdout.log"),
			StderrFile: runCtx.Run.Path("00_meta", "nuclei-update.stderr.log"),
		}
		if err := runner.AppendCommandLog(runCtx.Run.CommandsLog, updateCmd); err != nil {
			return nil, fmt.Errorf("failed to write commands log: %w", err)
		}
		if _, err := executor.Run(ctx, updateCmd); err != nil {
			return nil, fmt.Errorf("failed to update nuclei templates: %w", err)
		}
	}

	rawOutputFile := runCtx.Run.Path("06_vulns", "nuclei.jsonl")
	stderrFile := runCtx.Run.Path("00_meta", "nuclei.stderr.log")

	severity := opts.Severity
	if severity == "" {
		severity = "low,medium,high,critical"
	}
	// wafw00f having flagged a WAF changes the pacing defaults below: a
	// slower rate limit and lower bulk concurrency look less like a scanner
	// hammering every endpoint at once. Only applied when the operator
	// hasn't already chosen their own rate limit.
	waf := runCtx.GetWAFInfo()
	rateLimit := opts.RateLimit
	if rateLimit <= 0 {
		// nuclei's own default; ours used to be 10, which throttles a single
		// generic host's ~17000-request template sweep to ~20 minutes all by
		// itself, before a second host is even started.
		rateLimit = 150
		if waf.Detected {
			rateLimit = 40
		}
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Minute
	}

	args := []string{
		"-l", inputFile,
		"-silent",
		"-severity", severity,
		"-rate-limit", strconv.Itoa(rateLimit),
		"-jsonl",
		"-matcher-status",
		"-no-mhe",
		// Periodic JSON statistics on stderr (requests done/total, percent,
		// matches, rps): tailed below to feed the live progress line, so a
		// long scan never looks indistinguishable from a hung one.
		"-stats",
		"-stats-json",
		"-stats-interval", strconv.Itoa(statsIntervalSeconds),
	}
	// Automatic scan (-as) picks templates by the host's detected tech
	// instead of firing the full ~7000+ template catalog at every host: on a
	// plain site with nothing recognizable, that's the difference between
	// ~30 requests and ~17000. Skipped when the operator already narrowed
	// the run with explicit tags or a template path (their choice already
	// scopes the run) or explicitly asked for FullScan.
	if !opts.FullScan && opts.Tags == "" && opts.TemplatesDir == "" {
		args = append(args, "-as")
	}
	if opts.Headless {
		args = append(args, "-headless")
	}
	if opts.ExcludeSeverity != "" {
		args = append(args, "-exclude-severity", opts.ExcludeSeverity)
	}
	if opts.Tags != "" {
		args = append(args, "-tags", opts.Tags)
	}
	if opts.ExcludeTags != "" {
		args = append(args, "-exclude-tags", opts.ExcludeTags)
	}
	if opts.TemplatesDir != "" {
		args = append(args, "-t", opts.TemplatesDir)
	}
	if opts.IncludeCustomTemplates {
		customDir := opts.CustomTemplatesDir
		if customDir == "" {
			customDir = defaultCustomTemplatesDir()
		}
		if customDir != "" {
			args = append(args, "-t", customDir)
		}
	}
	if waf.Detected {
		// Lower bulk concurrency (nuclei's default is 25 hosts/templates in
		// flight at once) so the slower rate limit above isn't immediately
		// undone by a burst of parallel requests.
		args = append(args, "-c", "10")
		if !modules.HasHeaderNamed(runCtx.Headers, "User-Agent") {
			// Use a browser-like User-Agent instead of nuclei's own default
			// fingerprint, which a WAF can block outright. nuclei v3 has no
			// built-in rotation flag (-random-agent does not exist), so a
			// random one is picked per run, as ffuf and katana do.
			args = append(args, "-H", "User-Agent: "+modules.RandomUserAgent())
		}
	}
	args = append(args, runCtx.ProxyArgs("-proxy")...)
	args = append(args, runCtx.HeaderArgs("-H")...)

	cmd := runner.Command{
		Name:       m.binary,
		Args:       args,
		Timeout:    timeout,
		StdoutFile: rawOutputFile,
		StderrFile: stderrFile,
	}

	if err := runner.AppendCommandLog(runCtx.Run.CommandsLog, cmd); err != nil {
		return nil, fmt.Errorf("failed to write commands log: %w", err)
	}

	// Nuclei can run for tens of minutes; tail the JSONL it streams results
	// to so matches surface live instead of only once the whole scan ends.
	// tailDone is awaited (not fire-and-forget) so the final flush - which
	// picks up whatever nuclei wrote right before exiting - has actually run
	// before this module returns.
	stop := make(chan struct{})
	tailDone := make(chan struct{})
	statsDone := make(chan struct{})
	go func() {
		defer close(tailDone)
		modules.TailLines(rawOutputFile, stop, 500*time.Millisecond, func(line string) {
			emitNucleiFinding(runCtx, line)
		})
	}()
	// The stats stream shares stderr with nuclei's own diagnostics; only
	// lines that parse as a stats object become progress updates.
	go func() {
		defer close(statsDone)
		modules.TailLines(stderrFile, stop, time.Second, func(line string) {
			if s, ok := parseStats(line); ok {
				runCtx.EmitProgress(s.progressEvent(m.Name()))
			}
		})
	}()

	res, err := executor.Run(ctx, cmd)
	close(stop)
	<-tailDone
	<-statsDone

	// A stopped nuclei (timeout, cancellation, crash) may still have streamed
	// real matches to the JSONL file. Return the partial result alongside the
	// error so the orchestrator records the output files and the report engine
	// parses whatever was written instead of dropping everything.
	result := &modules.Result{
		Name:   m.Name(),
		Status: "failed",
		OutputFiles: map[string]string{
			"nuclei_raw":    "06_vulns/nuclei.jsonl",
			"nuclei_stderr": "00_meta/nuclei.stderr.log",
		},
	}
	if err != nil {
		return result, fmt.Errorf("failed to run command %q: %w", cmd.Name, err)
	}

	// Findings JSON is now generated by the unified Report Engine.

	if err := runCtx.AddArtifact("nuclei_raw", modules.Artifact{
		Name: "nuclei_raw",
		Type: "jsonl",
		Path: "06_vulns/nuclei.jsonl",
	}); err != nil {
		return nil, fmt.Errorf("failed to publish nuclei results: %w", err)
	}

	status := "completed"
	if res.ExitCode != 0 {
		status = fmt.Sprintf("failed (exit code %d)", res.ExitCode)
	}

	return &modules.Result{
		Name:   m.Name(),
		Status: status,
		OutputFiles: map[string]string{
			"nuclei_raw":    "06_vulns/nuclei.jsonl",
			"nuclei_stderr": "00_meta/nuclei.stderr.log",
		},
	}, nil
}

// emitNucleiFinding parses one line of nuclei's JSONL stream and, if it is a
// genuine match, reports it live via runCtx.EmitFinding. Malformed lines
// (e.g. a line read mid-write) and non-matches (matcher-status=false, used
// with OR-matcher templates) are silently skipped; the final report parser
// re-reads the completed file and is the source of truth.
func emitNucleiFinding(runCtx *modules.RunContext, line string) {
	var record struct {
		TemplateID    string `json:"template-id"`
		MatchedAt     string `json:"matched-at"`
		Host          string `json:"host"`
		MatcherStatus *bool  `json:"matcher-status"`
		Info          struct {
			Name     string `json:"name"`
			Severity string `json:"severity"`
		} `json:"info"`
	}
	if err := json.Unmarshal([]byte(line), &record); err != nil {
		return
	}
	if record.MatcherStatus != nil && !*record.MatcherStatus {
		return
	}

	target := record.Host
	if target == "" {
		target = record.MatchedAt
	}
	if target == "" {
		return
	}

	title := record.Info.Name
	if title == "" {
		title = record.TemplateID
	}

	runCtx.EmitFinding(modules.Finding{
		Module:   "nuclei",
		Severity: record.Info.Severity,
		Title:    title,
		Target:   target,
		Detail:   record.MatchedAt,
	})
}

// defaultCustomTemplatesDir locates the bundled custom template directory via
// SCANFORGE_TEMPLATES_DIR, the working directory or the executable directory,
// or "" when absent.
func defaultCustomTemplatesDir() string {
	if fromEnv := os.Getenv("SCANFORGE_TEMPLATES_DIR"); fromEnv != "" {
		if info, err := os.Stat(fromEnv); err == nil && info.IsDir() {
			return fromEnv
		}
	}
	for _, rel := range []string{"templates", filepath.Join("..", "templates")} {
		if abs, err := filepath.Abs(rel); err == nil {
			if info, err := os.Stat(abs); err == nil && info.IsDir() {
				return abs
			}
		}
	}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		for _, rel := range []string{"templates", filepath.Join("..", "templates")} {
			p := filepath.Join(dir, rel)
			if info, err := os.Stat(p); err == nil && info.IsDir() {
				return p
			}
		}
	}
	return ""
}
