package doctor

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/MikeRoss27/scanforge/internal/config"
)

type Severity string

const (
	SeverityOK       Severity = "ok"
	SeverityWarn     Severity = "warn"
	SeverityFail     Severity = "fail"
	SeverityRequired Severity = "required"
)

type Check struct {
	Name     string   `json:"name"`
	Status   Severity `json:"status"`
	Message  string   `json:"message"`
	Required bool     `json:"required"`
}

type Options struct {
	Profile string
	JSON    bool
	Verbose bool
	Config  *config.Config
}

type ToolChecker interface {
	CheckTool(ctx context.Context, name, binary string, verbose bool) Check
}

type DefaultToolChecker struct{}

func (DefaultToolChecker) CheckTool(ctx context.Context, name, binary string, verbose bool) Check {
	check := Check{
		Name:     name,
		Required: true,
	}

	path, err := exec.LookPath(binary)
	if err != nil {
		check.Status = SeverityFail
		check.Message = fmt.Sprintf("not found in PATH (configured as %q)", binary)
		return check
	}

	versionOutput, versionErr := runVersionCommand(ctx, path)
	if versionErr != nil {
		check.Status = SeverityWarn
		check.Message = fmt.Sprintf("found at %s but version check failed: %v", path, versionErr)
		return check
	}

	check.Status = SeverityOK
	if verbose {
		check.Message = fmt.Sprintf("%s (%s)", strings.TrimSpace(versionOutput), path)
	} else {
		check.Message = strings.TrimSpace(versionOutput)
		if check.Message == "" {
			check.Message = path
		}
	}

	return check
}

type Runner struct {
	checker ToolChecker
}

func New(checker ToolChecker) *Runner {
	if checker == nil {
		checker = DefaultToolChecker{}
	}
	return &Runner{checker: checker}
}

func (r *Runner) Run(ctx context.Context, opts Options) ([]Check, int, error) {
	cfg := opts.Config
	if cfg == nil {
		cfg = config.Default()
	}

	profile := opts.Profile
	if profile == "" {
		profile = cfg.DefaultProfile
	}

	checks := make([]Check, 0, 8)

	moduleNames, err := cfg.ProfileModules(profile)
	if err != nil {
		// fallback to empty set if profile is unknown
		moduleNames = []string{}
	}
	moduleSet := make(map[string]bool)
	for _, m := range moduleNames {
		moduleSet[m] = true
	}

	requiredTools := []struct {
		name   string
		binary string
	}{
		{name: "subfinder", binary: cfg.ToolPath("subfinder")},
		{name: "dnsx", binary: cfg.ToolPath("dnsx")},
		{name: "httpx", binary: cfg.ToolPath("httpx")},
		{name: "naabu", binary: cfg.ToolPath("naabu")},
		{name: "nmap", binary: cfg.ToolPath("nmap")},
		{name: "whatweb", binary: cfg.ToolPath("whatweb")},
		{name: "wafw00f", binary: cfg.ToolPath("wafw00f")},
		{name: "katana", binary: cfg.ToolPath("katana")},
		{name: "ffuf", binary: cfg.ToolPath("ffuf")},
		{name: "nuclei", binary: cfg.ToolPath("nuclei")},
	}

	for _, tool := range requiredTools {
		if len(moduleSet) > 0 && !moduleSet[tool.name] {
			continue
		}

		check := r.checker.CheckTool(ctx, tool.name, tool.binary, opts.Verbose)
		check.Required = true
		checks = append(checks, check)
	}

	checks = append(checks, checkWorkspace(cfg))
	checks = append(checks, checkConfigFile())
	checks = append(checks, checkScopeFile(cfg))

	exitCode := 0
	for _, check := range checks {
		if check.Required && check.Status == SeverityFail {
			exitCode = 1
		}
	}

	return checks, exitCode, nil
}

func checkWorkspace(cfg *config.Config) Check {
	dir := config.WorkspaceDir(cfg)
	check := Check{
		Name:     "workspace",
		Required: true,
	}

	if err := os.MkdirAll(dir, 0755); err != nil {
		check.Status = SeverityFail
		check.Message = fmt.Sprintf("unable to create %q: %v", dir, err)
		return check
	}

	testFile := filepath.Join(dir, ".doctor-write-test")
	if err := os.WriteFile(testFile, []byte("ok"), 0644); err != nil {
		check.Status = SeverityFail
		check.Message = fmt.Sprintf("directory %q is not writable: %v", dir, err)
		return check
	}
	_ = os.Remove(testFile)

	check.Status = SeverityOK
	check.Message = fmt.Sprintf("writable (%s)", dir)
	return check
}

func checkConfigFile() Check {
	check := Check{
		Name:     "config",
		Required: false,
	}

	path := config.ResolvePath("")
	if _, err := os.Stat(path); err != nil {
		check.Status = SeverityWarn
		check.Message = fmt.Sprintf("%s not found (run: scanforge init)", path)
		return check
	}

	if _, err := config.Load(path); err != nil {
		check.Status = SeverityFail
		check.Message = fmt.Sprintf("%s is invalid: %v", path, err)
		check.Required = false
		return check
	}

	check.Status = SeverityOK
	check.Message = path
	return check
}

func checkScopeFile(cfg *config.Config) Check {
	check := Check{
		Name:     "scope",
		Required: false,
	}

	path := cfg.DefaultScope
	if path == "" {
		path = config.DefaultScope
	}

	info, err := os.Stat(path)
	if err != nil {
		check.Status = SeverityWarn
		check.Message = fmt.Sprintf("%s not found (run: scanforge init)", path)
		return check
	}

	if info.Size() == 0 {
		check.Status = SeverityWarn
		check.Message = fmt.Sprintf("%s is empty", path)
		return check
	}

	check.Status = SeverityOK
	check.Message = path
	return check
}

func runVersionCommand(ctx context.Context, binary string) (string, error) {
	args := [][]string{
		{"-version"},
		{"-v"},
		{"version"},
	}

	var lastErr error
	for _, arg := range args {
		cmd := exec.CommandContext(ctx, binary, arg...)
		output, err := cmd.CombinedOutput()
		if err == nil {
			return string(output), nil
		}
		lastErr = err
	}

	return "", lastErr
}

func FormatChecks(checks []Check) string {
	var b strings.Builder

	passed := 0
	failed := 0
	warned := 0

	for _, check := range checks {
		label := string(check.Status)
		switch check.Status {
		case SeverityOK:
			label = "✓"
			passed++
		case SeverityWarn:
			label = "!"
			warned++
		case SeverityFail:
			label = "✗"
			if check.Required {
				failed++
			}
		}

		fmt.Fprintf(&b, "  [%s] %-10s %s\n", label, check.Name, check.Message)
	}

	fmt.Fprintf(&b, "\n%d passed", passed)
	if failed > 0 {
		fmt.Fprintf(&b, ", %d failed", failed)
	}
	if warned > 0 {
		fmt.Fprintf(&b, ", %d warning(s)", warned)
	}
	b.WriteString("\n")

	return b.String()
}

func FormatChecksJSON(checks []Check) (string, error) {
	data, err := json.MarshalIndent(checks, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}
