package cli

import (
	"strings"
	"time"

	"github.com/MikeRoss27/scanforge/internal/app"
	"github.com/MikeRoss27/scanforge/internal/config"
	"github.com/MikeRoss27/scanforge/internal/console"
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
	var verbosityCount int
	var quiet bool

	var proxy string
	var eventsEnabled bool
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
	var nucleiFullScan bool

	var nmapConcurrency int

	var limitConcurrency int
	var limitRPS float64
	var limitMaxRequests int
	var limitCommandTimeout time.Duration

	var ffufWordlist string
	var ffufFilterCodes string

	var wp bool
	var wpDetectionMode string
	var wpWordlist string
	var wpBruteforce bool
	var wpPasswords string
	var wpBruteMethod string
	var wpBruteforceMax int

	cmd := &cobra.Command{
		Use:         "run [target]",
		Aliases:     []string{"scan"},
		GroupID:     groupCore,
		Annotations: map[string]string{annGroupedFlags: "true"},
		Short:       "Run a scan against an authorized target",
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
				Verbosity:    console.ParseVerbosity(verbosityCount, quiet),
				Proxy:        proxy,
				Headers:      headers,
				Events:       eventsEnabled,
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
					FullScan:               nucleiFullScan,
				},
				NmapConcurrency: nmapConcurrency,
				Limits: config.Limits{
					Concurrency:    limitConcurrency,
					RPS:            limitRPS,
					MaxRequests:    limitMaxRequests,
					CommandTimeout: limitCommandTimeout,
				},
				Ffuf: modules.FfufOptions{
					Wordlist:    ffufWordlist,
					FilterCodes: ffufFilterCodes,
				},
				WP: wp,
				WordPress: modules.WordPressOptions{
					DetectionMode: wpDetectionMode,
					Wordlist:      wpWordlist,
					Bruteforce:    wpBruteforce,
					PasswordsFile: wpPasswords,
					BruteMax:      wpBruteforceMax,
					BruteMethod:   wpBruteMethod,
				},
			})
		},
	}

	cmd.Flags().StringVarP(&profile, "profile", "p", "", "Scan profile to run (default from config)")
	cmd.Flags().StringVar(&preset, "preset", "", "Built-in preset (safe, recon, web, ports, vuln, deep, wp)")
	cmd.Flags().StringVar(&targetsFile, "targets", "", "Read one target per line from a file (replaces [target])")
	cmd.Flags().StringVarP(&scopeFile, "scope", "s", "", "Scope file (default from config)")
	cmd.Flags().StringVar(&scopeMode, "scope-mode", "", "Implicit scope mode: exact or domain (default domain for DNS domains, exact for IPs and single-label hosts)")
	cmd.Flags().StringArrayVar(&scopeAdd, "scope-add", nil, "Add an entry to implicit scope (repeatable)")
	cmd.Flags().StringArrayVar(&exclusions, "exclude", nil, "Exclude an entry from implicit scope (repeatable)")
	cmd.Flags().BoolVar(&confirmScope, "confirm-scope", false, "Confirm the effective scope non-interactively (required in CI)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Print commands without executing them")
	cmd.Flags().CountVarP(&verbosityCount, "verbose", "v", "Increase verbosity: -v detailed modules, -vv commands, -vvv redirections")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Only findings, warnings, errors and the summary")

	cmd.Flags().BoolVar(&eventsEnabled, "events", false, "Experimental: emit discovery events (subdomains -> DNS_NAME) to 00_meta/events.jsonl, scope-gated")
	cmd.Flags().StringVar(&proxy, "proxy", "", "Route HTTP-capable modules through a proxy, e.g. Caido/Burp at http://127.0.0.1:8080")
	cmd.Flags().StringArrayVarP(&headers, "header", "H", nil, "Custom HTTP header sent with every request, e.g. 'Authorization: Bearer <token>' (repeatable)")

	cmd.Flags().StringVar(&nucleiSeverity, "nuclei-severity", "", "Nuclei: comma-separated severities to run (default low,medium,high,critical)")
	cmd.Flags().StringVar(&nucleiExcludeSeverity, "nuclei-exclude-severity", "", "Nuclei: comma-separated severities to skip")
	cmd.Flags().StringVar(&nucleiTags, "nuclei-tags", "", "Nuclei: comma-separated template tags to run")
	cmd.Flags().StringVar(&nucleiExcludeTags, "nuclei-exclude-tags", "", "Nuclei: comma-separated template tags to skip")
	cmd.Flags().IntVar(&nucleiRateLimit, "nuclei-rate-limit", 0, "Nuclei: max requests per second (default 150, nuclei's own default)")
	cmd.Flags().DurationVar(&nucleiTimeout, "nuclei-timeout", 0, "Nuclei: overall time limit, e.g. 45m (default 30m; raise it for slow proxies, --nuclei-full-scan, or large target lists)")
	cmd.Flags().StringVar(&nucleiTemplates, "nuclei-templates", "", "Nuclei: custom template file or directory to run instead of the default set")
	cmd.Flags().BoolVar(&nucleiUpdateTemplates, "nuclei-update-templates", false, "Nuclei: update the local template cache before scanning")
	cmd.Flags().BoolVar(&nucleiHeadless, "nuclei-headless", false, "Nuclei: enable headless-mode templates (requires nuclei headless support)")
	cmd.Flags().BoolVar(&nucleiIncludeCustom, "nuclei-include-custom", false, "Nuclei: also run the bundled ScanForge custom templates")
	cmd.Flags().BoolVar(&nucleiFullScan, "nuclei-full-scan", false, "Nuclei: run every template against every host instead of nuclei's technology-aware automatic scan (-as); much slower, raise --nuclei-timeout to match")

	cmd.Flags().IntVar(&limitConcurrency, "concurrency", 0, "Global cap on commands running at once (overrides limits.concurrency; 0 = config/unlimited)")
	cmd.Flags().Float64Var(&limitRPS, "rps", 0, "Global cap on command launches per second; also lowers tools' own rate flags (overrides limits.rps)")
	cmd.Flags().IntVar(&limitMaxRequests, "max-requests", 0, "Global budget of commands per run; later commands fail once spent (overrides limits.max_requests)")
	cmd.Flags().DurationVar(&limitCommandTimeout, "command-timeout", 0, "Upper bound for every command's timeout, e.g. 20m (overrides limits.command_timeout)")
	cmd.Flags().IntVar(&nmapConcurrency, "nmap-concurrency", 0, "Max concurrent nmap processes (default 4; lower to reduce noise)")

	cmd.Flags().StringVar(&ffufWordlist, "ffuf-wordlist", "", "Path to an ffuf wordlist (default: auto-detect)")
	cmd.Flags().StringVar(&ffufFilterCodes, "ffuf-filter-codes", "", "Ffuf: comma-separated HTTP status codes to filter out, e.g. 404,500")

	cmd.Flags().BoolVar(&wp, "wp", false, "Add the WordPress engagement chain (wpdetect, plugins/themes, users, exposure, XML-RPC, CVE) to the selected profile")
	cmd.Flags().StringVar(&wpDetectionMode, "wp-detection-mode", "passive", "WordPress plugin/theme probing: passive (default, crawl artifacts only), mixed, or aggressive (probe readme.txt for each slug)")
	cmd.Flags().StringVar(&wpWordlist, "wp-wordlist", "", "WordPress slug wordlist for aggressive mode (one slug per line); defaults to the bundled top list")
	cmd.Flags().BoolVar(&wpBruteforce, "wp-bruteforce", false, "Enable the wpbrute module (OFF by default; also requires --confirm-scope and --wp-passwords)")
	cmd.Flags().StringVar(&wpPasswords, "wp-passwords", "", "Password wordlist for wpbrute (required with --wp-bruteforce; none is bundled)")
	cmd.Flags().StringVar(&wpBruteMethod, "wp-brute-method", "login", "Auth probe for wpbrute: login (wp-login.php form, default) or xmlrpc (wp.getUsersBlogs)")
	cmd.Flags().IntVar(&wpBruteforceMax, "wp-bruteforce-max", 100, "Max passwords tried per user with wpbrute (default 100)")

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
		case strings.HasPrefix(flag.Name, "nuclei-"), strings.HasPrefix(flag.Name, "nmap-"), strings.HasPrefix(flag.Name, "ffuf-"), strings.HasPrefix(flag.Name, "wp-"), flag.Name == "wp":
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
