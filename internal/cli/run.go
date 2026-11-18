package cli

import (
	"strings"
	"time"

	"github.com/MikeRoss27/scanforge/internal/app"
	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func NewRunCommand(application *app.App) *cobra.Command {
	var profile string
	var preset string
	var scopeFile string
	var scopeMode string
	var scopeAdd []string
	var exclusions []string
	var targetsFile string
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
	var nucleiTimeout time.Duration
	var nucleiTemplates string
	var nucleiUpdateTemplates bool
	var nucleiHeadless bool
	var nucleiIncludeCustom bool

	var nmapConcurrency int

	var ffufWordlist string
	var ffufFilterCodes string

	cmd := &cobra.Command{
		Use:     "run [target]",
		Aliases: []string{"scan"},
		GroupID: groupCore,
		Short:   "Run a scan against an authorized target",
		Long: `Executes the scan pipeline for a target (or a list of targets) using
the selected profile or preset. The effective scope is built from scope.txt
and every artifact is filtered against it before downstream modules consume
it. Results are written to runs/<target>/<timestamp>/ with a consolidated
report (report.json / report.md).`,
		Example: `  scanforge run example.com
  scanforge run --targets targets.txt --profile web
  scanforge run example.com --dry-run`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// --profile takes precedence; --preset is shorthand for one of
			// the built-in profile names.
			if profile == "" {
				profile = preset
			}
			var target string
			if len(args) > 0 {
				target = args[0]
			}
			return application.Run(cmd.Context(), app.RunOptions{
				Target:       target,
				TargetsFile:  targetsFile,
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
					Timeout:                nucleiTimeout,
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
	cmd.Flags().StringVar(&preset, "preset", "", "Built-in preset (safe, recon, web, ports, vuln, deep)")
	cmd.Flags().StringVar(&targetsFile, "targets", "", "Read one target per line from a file (replaces [target])")
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
	cmd.Flags().DurationVar(&nucleiTimeout, "nuclei-timeout", 0, "Nuclei: overall time limit, e.g. 45m (default 30m; raise it for slow proxies or large target lists)")
	cmd.Flags().StringVar(&nucleiTemplates, "nuclei-templates", "", "Nuclei: custom template file or directory to run instead of the default set")
	cmd.Flags().BoolVar(&nucleiUpdateTemplates, "nuclei-update-templates", false, "Nuclei: update the local template cache before scanning")
	cmd.Flags().BoolVar(&nucleiHeadless, "nuclei-headless", false, "Nuclei: enable headless-mode templates (requires nuclei headless support)")
	cmd.Flags().BoolVar(&nucleiIncludeCustom, "nuclei-include-custom", false, "Nuclei: also run the bundled ScanForge custom templates")

	cmd.Flags().IntVar(&nmapConcurrency, "nmap-concurrency", 0, "Max concurrent nmap processes (default 4; lower to reduce noise)")

	cmd.Flags().StringVar(&ffufWordlist, "ffuf-wordlist", "", "Path to an ffuf wordlist (default: auto-detect)")
	cmd.Flags().StringVar(&ffufFilterCodes, "ffuf-filter-codes", "", "Ffuf: comma-separated HTTP status codes to filter out, e.g. 404,500")

	return cmd
}

// runFlagHelp groups the existing options without changing how Cobra parses them.
func runFlagHelp(cmd *cobra.Command) string {
	headings := []string{"Scan options", "Scope options", "HTTP options", "Tool options"}
	groups := make([]*pflag.FlagSet, len(headings))
	for i, heading := range headings {
		groups[i] = pflag.NewFlagSet(heading, pflag.ContinueOnError)
	}
	cmd.LocalFlags().VisitAll(func(flag *pflag.Flag) {
		switch {
		case strings.HasPrefix(flag.Name, "scope"), flag.Name == "exclude", flag.Name == "confirm-scope":
			groups[1].AddFlag(flag)
		case flag.Name == "proxy", flag.Name == "header":
			groups[2].AddFlag(flag)
		case strings.HasPrefix(flag.Name, "nuclei-"), strings.HasPrefix(flag.Name, "nmap-"), strings.HasPrefix(flag.Name, "ffuf-"):
			groups[3].AddFlag(flag)
		default:
			groups[0].AddFlag(flag)
		}
	})

	var sections []string
	for i, group := range groups {
		if flags := strings.TrimRight(group.FlagUsagesWrapped(80), " \t\n"); flags != "" {
			sections = append(sections, headings[i]+":\n"+flags)
		}
	}
	return strings.Join(sections, "\n\n")
}

func init() {
	cobra.AddTemplateFunc("runFlagHelp", runFlagHelp)
}
