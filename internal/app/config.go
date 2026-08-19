package app

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/MikeRoss27/scanforge/internal/config"
	"github.com/MikeRoss27/scanforge/internal/profile"
	scanscope "github.com/MikeRoss27/scanforge/internal/scope"
	"github.com/MikeRoss27/scanforge/internal/ui"
)

// ValidateConfigResult is the outcome of a config validation: the resolved
// config path plus problems (hard errors) and warnings (soft issues).
type ValidateConfigResult struct {
	Path     string
	Problems []string
	Warnings []string
}

// ValidateConfig loads scanforge.yaml and checks that it is usable: supported
// config version, resolvable default profile, custom profiles referencing only
// known modules, custom tool paths that exist on disk, and a parseable
// default scope file. A missing default scope file is only a warning: it is
// the normal state before `scanforge init` has run.
func (a *App) ValidateConfig(ctx context.Context) (*ValidateConfigResult, error) {
	path := config.ResolvePath(a.ConfigPath)
	cfg, err := config.Load(path)
	if err != nil {
		return nil, err
	}

	result := &ValidateConfigResult{Path: path}

	if cfg.ConfigVersion != config.DefaultConfigVersion {
		result.Problems = append(result.Problems,
			fmt.Sprintf("config_version %d is not supported (expected %d)", cfg.ConfigVersion, config.DefaultConfigVersion))
	}

	if _, err := profile.Resolve(cfg.DefaultProfile, cfg.Profiles); err != nil {
		result.Problems = append(result.Problems,
			fmt.Sprintf("default_profile %q: %v", cfg.DefaultProfile, err))
	}

	registry := buildRegistry(cfg)
	profileNames := make([]string, 0, len(cfg.Profiles))
	for name := range cfg.Profiles {
		profileNames = append(profileNames, name)
	}
	sort.Strings(profileNames)
	for _, name := range profileNames {
		for _, moduleName := range cfg.Profiles[name] {
			if _, ok := registry.Get(moduleName); !ok {
				result.Problems = append(result.Problems,
					fmt.Sprintf("profile %q references unknown module %q", name, moduleName))
			}
		}
	}

	for name := range cfg.ModuleTimeouts {
		if _, ok := registry.Get(name); !ok {
			result.Problems = append(result.Problems,
				fmt.Sprintf("module_timeouts references unknown module %q", name))
		}
	}

	if cfg.AI.Model != "" || cfg.AI.BaseURL != "" || cfg.AI.APIKey != "" {
		if cfg.AI.BaseURL == "" {
			result.Problems = append(result.Problems,
				"ai.base_url is required when the ai section is configured (e.g. http://127.0.0.1:8080/v1)")
		} else if parsed, err := url.Parse(cfg.AI.BaseURL); err != nil || parsed.Hostname() == "" {
			result.Problems = append(result.Problems,
				fmt.Sprintf("ai.base_url %q is not a valid URL", cfg.AI.BaseURL))
		}
		if cfg.AI.Model == "" {
			result.Problems = append(result.Problems,
				"ai.model is required when the ai section is configured")
		}
		if cfg.AI.Temperature < 0 || cfg.AI.Temperature > 2 {
			result.Problems = append(result.Problems,
				fmt.Sprintf("ai.temperature %v is out of range (expected 0.0-2.0)", cfg.AI.Temperature))
		}
	}

	for tool, toolPath := range customToolPaths(cfg) {
		if _, err := os.Stat(toolPath); err != nil {
			result.Problems = append(result.Problems,
				fmt.Sprintf("tool %q path %q does not exist", tool, toolPath))
		}
	}

	if cfg.DefaultScope != "" {
		if _, err := scanscope.LoadFromFile(cfg.DefaultScope); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				result.Warnings = append(result.Warnings,
					fmt.Sprintf("default_scope file %q not found (run `scanforge init`)", cfg.DefaultScope))
			} else {
				result.Problems = append(result.Problems,
					fmt.Sprintf("default_scope file %q: %v", cfg.DefaultScope, err))
			}
		}
	}

	return result, nil
}

// customToolPaths returns the tools whose configured path is not a bare
// command name (those are resolved through PATH at run time and cannot be
// statically checked).
func customToolPaths(cfg *config.Config) map[string]string {
	paths := map[string]string{
		"subfinder":  cfg.Tools.Subfinder,
		"dnsx":       cfg.Tools.Dnsx,
		"httpx":      cfg.Tools.Httpx,
		"naabu":      cfg.Tools.Naabu,
		"nmap":       cfg.Tools.Nmap,
		"whatweb":    cfg.Tools.Whatweb,
		"wafw00f":    cfg.Tools.Wafw00f,
		"katana":     cfg.Tools.Katana,
		"ffuf":       cfg.Tools.Ffuf,
		"nuclei":     cfg.Tools.Nuclei,
		"gau":        cfg.Tools.Gau,
		"tlsx":       cfg.Tools.Tlsx,
		"shuffledns": cfg.Tools.Shuffledns,
		"chromium":   cfg.Tools.Chromium,
	}
	for name, path := range paths {
		if path == "" || !strings.ContainsAny(path, `/\`) {
			delete(paths, name)
		}
	}
	return paths
}

// PrintValidateConfig renders the validation result and returns an
// ExitCodeError when problems were found, so the shell sees a failing
// command without os.Exit in library code.
func (a *App) PrintValidateConfig(result *ValidateConfigResult) error {
	fmt.Println(ui.Bold(ui.Primary("ScanForge Config Validation")))
	fmt.Println()
	fmt.Printf("Config file: %s\n", result.Path)

	if len(result.Problems) == 0 && len(result.Warnings) == 0 {
		fmt.Println()
		ui.Success("Configuration is valid.")
		return nil
	}

	if len(result.Problems) > 0 {
		fmt.Println()
		fmt.Println(ui.Header("Problems", ui.AccentRed))
		for _, problem := range result.Problems {
			fmt.Printf("  - %s\n", problem)
		}
	}
	if len(result.Warnings) > 0 {
		fmt.Println()
		fmt.Println(ui.Header("Warnings", ui.AccentYellow))
		for _, warning := range result.Warnings {
			fmt.Printf("  - %s\n", warning)
		}
	}

	if len(result.Problems) > 0 {
		return ExitCodeError{Code: 1}
	}
	return nil
}
