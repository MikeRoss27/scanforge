package app

import (
	"context"
	"fmt"

	"github.com/MikeRoss27/scanforge/internal/doctor"
	"github.com/MikeRoss27/scanforge/internal/initcmd"
	"github.com/MikeRoss27/scanforge/internal/ui"
	"github.com/MikeRoss27/scanforge/internal/version"
)

// Doctor checks the local environment (tools, workspace, config) for the
// selected profile and reports the results, exiting non-zero when a required
// tool is missing.
func (a *App) Doctor(ctx context.Context, opts DoctorOptions) error {
	cfg, err := a.loadConfig()
	if err != nil {
		return err
	}

	runner := doctor.New(nil)
	checks, exitCode, err := runner.Run(ctx, doctor.Options{
		Profile: opts.Profile,
		JSON:    opts.JSON,
		Verbose: opts.Verbose,
		Config:  cfg,
	})
	if err != nil {
		return err
	}

	if opts.JSON {
		output, err := doctor.FormatChecksJSON(checks)
		if err != nil {
			return err
		}
		fmt.Println(output)
	} else {
		fmt.Println(ui.Bold(ui.Primary("ScanForge Doctor v" + version.Version)))
		fmt.Println()
		fmt.Print(doctor.FormatChecks(checks))
	}

	if exitCode != 0 {
		return ExitCodeError{Code: exitCode}
	}

	return nil
}

// Init creates the default configuration files (scanforge.yaml, scope.txt)
// in the current directory.
func (a *App) Init(ctx context.Context, opts InitOptions) error {
	result, err := initcmd.Run(initcmd.Options{Force: opts.Force})
	if err != nil {
		for _, path := range result.Created {
			ui.Success("Created: %s", path)
		}
		for _, path := range result.Skipped {
			ui.Info("Skipped: %s", path)
		}
		return err
	}

	for _, path := range result.Created {
		ui.Success("Created: %s", path)
	}
	for _, path := range result.Skipped {
		ui.Info("Skipped: %s", path)
	}

	fmt.Println()
	fmt.Println(ui.Header("Initialization Complete", ui.AccentGreen))

	ui.Info("Next steps:")
	fmt.Printf("  %s %s\n", ui.Primary("1."), ui.Bold("scanforge doctor"))
	fmt.Printf("  %s %s\n", ui.Primary("2."), ui.Bold("scanforge plan example.com"))
	fmt.Printf("  %s %s\n", ui.Primary("3."), ui.Bold("scanforge run example.com --dry-run"))
	fmt.Printf("  %s %s\n", ui.Primary("4."), ui.Bold("scanforge run example.com"))

	return nil
}
