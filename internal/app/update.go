package app

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	
	"github.com/pterm/pterm"
)

type UpdateOptions struct {
	Tools bool
}

func (a *App) Update(ctx context.Context, opts UpdateOptions) error {
	if _, err := exec.LookPath("go"); err != nil {
		return fmt.Errorf("the 'go' command was not found in PATH, which is required for updating: %w", err)
	}

	pterm.Info.Println("Updating scanforge...")
	cmd := exec.CommandContext(ctx, "go", "install", "github.com/MikeRoss27/scanforge/cmd/scanforge@latest")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to update scanforge: %w", err)
	}
	pterm.Success.Println("ScanForge updated successfully.")

	if opts.Tools {
		tools := []string{
			"github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
			"github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
			"github.com/projectdiscovery/httpx/cmd/httpx@latest",
			"github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
			"github.com/projectdiscovery/katana/cmd/katana@latest",
			"github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
			"github.com/ffuf/ffuf/v2@latest",
		}
		pterm.Println()
		pterm.Info.Println("Updating external tools...")
		for _, tool := range tools {
			spinner, _ := pterm.DefaultSpinner.Start(fmt.Sprintf("Updating %s ...", tool))
			tcmd := exec.CommandContext(ctx, "go", "install", tool)
			
			if err := tcmd.Run(); err != nil {
				spinner.Warning(fmt.Sprintf("Failed to update %s: %v", tool, err))
			} else {
				spinner.Success(fmt.Sprintf("Updated %s", tool))
			}
		}
		pterm.Success.Println("External tools updated.")
	}

	return nil
}
