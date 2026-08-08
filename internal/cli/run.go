package cli

import (
	"github.com/MikeRoss27/scanforge/internal/app"
	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/spf13/cobra"
)

func NewRunCommand(application *app.App) *cobra.Command {
	var profile string
	var preset string
	var scopeFile string
	var scopeMode string
	var scopeAdd []string
	var exclusions []string
	var confirmScope bool
	var dryRun bool
	var verbose bool

	var proxy string
	var headers []string

	var nucleiSeverity string
	var nucleiExcludeSeverity string
	var nucleiTags string
	var nucleiExcludeTags string
	var nucleiRateLimit int
	var nucleiTemplates string
	var nucleiUpdateTemplates bool
	var nucleiHeadless bool
	var nucleiIncludeCustom bool

	var nmapConcurrency int

	var ffufWordlist string
	var ffufFilterCodes string

	cmd := &cobra.Command{
		Use:     "run <target>",
		Aliases: []string{"scan"},
		Short:   "Run a scan profile against an authorized target",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// --profile takes precedence; --preset is shorthand for one of
			// the built-in profile names.
			if profile == "" {
				profile = preset
			}
			return application.Run(cmd.Context(), app.RunOptions{
				Target:       args[0],
				Profile:      profile,
				Scope:        scopeFile,
				ScopeMode:    scopeMode,
				ScopeAdd:     scopeAdd,
				Exclusions:   exclusions,
				ConfirmScope: confirmScope,
				DryRun:       dryRun,
				Verbose:      verbose,
				Proxy:        proxy,
				Headers:      headers,
				Nuclei: modules.NucleiOptions{
					Severity:               nucleiSeverity,
					ExcludeSeverity:        nucleiExcludeSeverity,
					Tags:                   nucleiTags,
					ExcludeTags:            nucleiExcludeTags,
					RateLimit:              nucleiRateLimit,
					TemplatesDir:           nucleiTemplates,
					UpdateTemplates:        nucleiUpdateTemplates,
					Headless:               nucleiHeadless,
					IncludeCustomTemplates: nucleiIncludeCustom,
				},
				NmapConcurrency: nmapConcurrency,
				Ffuf: modules.FfufOptions{
					Wordlist:    ffufWordlist,
					FilterCodes: ffufFilterCodes,
				},
			})
		},
	}

	cmd.Flags().StringVarP(&profile, "profile", "p", "", "Scan profile to run (default from config)")
	cmd.Flags().StringVar(&preset, "preset", "", "User-oriented preset (safe, recon, web, ports, vuln, deep)")
	cmd.Flags().StringVarP(&scopeFile, "scope", "s", "", "Scope file (default from config)")
	cmd.Flags().StringVar(&scopeMode, "scope-mode", "", "Implicit scope mode: exact or domain (default exact)")
	cmd.Flags().StringArrayVar(&scopeAdd, "scope-add", nil, "Add an entry to implicit scope (repeatable)")
	cmd.Flags().StringArrayVar(&exclusions, "exclude", nil, "Exclude an entry from implicit scope (repeatable)")
	cmd.Flags().BoolVar(&confirmScope, "confirm-scope", false, "Confirm the effective scope non-interactively (required in CI)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Print commands without executing them")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")

	cmd.Flags().StringVar(&proxy, "proxy", "", "Route HTTP-capable modules through a proxy, e.g. Caido/Burp at http://127.0.0.1:8080")
	cmd.Flags().StringArrayVarP(&headers, "header", "H", nil, "Custom HTTP header sent with every request, e.g. 'Authorization: Bearer <token>' (repeatable)")

	cmd.Flags().StringVar(&nucleiSeverity, "nuclei-severity", "", "Nuclei: comma-separated severities to run (default low,medium,high,critical)")
	cmd.Flags().StringVar(&nucleiExcludeSeverity, "nuclei-exclude-severity", "", "Nuclei: comma-separated severities to skip")
	cmd.Flags().StringVar(&nucleiTags, "nuclei-tags", "", "Nuclei: comma-separated template tags to run")
	cmd.Flags().StringVar(&nucleiExcludeTags, "nuclei-exclude-tags", "", "Nuclei: comma-separated template tags to skip")
	cmd.Flags().IntVar(&nucleiRateLimit, "nuclei-rate-limit", 0, "Nuclei: max requests per second (default 10)")
	cmd.Flags().StringVar(&nucleiTemplates, "nuclei-templates", "", "Nuclei: custom template file or directory to run instead of the default set")
	cmd.Flags().BoolVar(&nucleiUpdateTemplates, "nuclei-update-templates", false, "Nuclei: update the local template cache before scanning")
	cmd.Flags().BoolVar(&nucleiHeadless, "nuclei-headless", false, "Nuclei: enable headless-mode templates (requires nuclei headless support)")
	cmd.Flags().BoolVar(&nucleiIncludeCustom, "nuclei-include-custom", false, "Nuclei: also run the bundled ScanForge custom templates")

	cmd.Flags().IntVar(&nmapConcurrency, "nmap-concurrency", 0, "Max concurrent nmap processes (default 4; lower to reduce noise)")

	cmd.Flags().StringVar(&ffufWordlist, "ffuf-wordlist", "", "Ffuf: wordlist of paths to fuzz (default /usr/share/wordlists/dirb/common.txt)")
	cmd.Flags().StringVar(&ffufFilterCodes, "ffuf-filter-codes", "", "Ffuf: comma-separated HTTP status codes to filter out, e.g. 404,500")

	return cmd
}
