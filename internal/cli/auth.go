package cli

import (
	"fmt"
	"strings"

	"github.com/MikeRoss27/scanforge/internal/app"
	"github.com/MikeRoss27/scanforge/internal/auth"
	"github.com/spf13/cobra"
)

func NewAuthCommand(app *app.App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Manage API keys and authentication for security tools",
		Long:  `Manage API keys for underlying tools like subfinder, nuclei, etc.`,
	}

	setCmd := &cobra.Command{
		Use:   "set [provider] [api_key]",
		Short: "Set an API key for a specific provider (e.g. shodan, github, chaos)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			provider := strings.ToLower(args[0])
			key := args[1]

			cfg, err := auth.Load()
			if err != nil {
				return err
			}

			cfg.SetKey(provider, key)
			if err := cfg.Save(); err != nil {
				return fmt.Errorf("failed to save auth config: %w", err)
			}

			fmt.Printf("API key for %q saved successfully.\n", provider)
			fmt.Println("Run 'scanforge auth sync' to apply the keys to the tools.")
			return nil
		},
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List configured API providers",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := auth.Load()
			if err != nil {
				return err
			}

			if len(cfg.Providers) == 0 {
				fmt.Println("No API keys configured.")
				return nil
			}

			fmt.Println("Configured API Providers:")
			for provider, keys := range cfg.Providers {
				if key, ok := keys["api_key"]; ok {
					masked := "****"
					if len(key) > 4 {
						masked += key[len(key)-4:]
					}
					fmt.Printf("- %s: %s\n", provider, masked)
				}
			}
			return nil
		},
	}

	syncCmd := &cobra.Command{
		Use:   "sync",
		Short: "Synchronize API keys with underlying tools configurations",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := auth.Load()
			if err != nil {
				return err
			}
			return cfg.Sync()
		},
	}

	cmd.AddCommand(setCmd)
	cmd.AddCommand(listCmd)
	cmd.AddCommand(syncCmd)

	return cmd
}
