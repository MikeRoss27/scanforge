package console

// Verbosity is the structured output level of the console renderer.
type Verbosity int

const (
	// Quiet (-q) keeps findings, warnings, errors and the final summary, and
	// drops the banner, header, phases and module lifecycle noise.
	Quiet Verbosity = -1
	// Normal is the default: phases, module lifecycle, findings, warnings,
	// errors and the summary.
	Normal Verbosity = 0
	// Verbose (-v) adds wave numbers and extra context on skipped modules.
	Verbose Verbosity = 1
	// Debug (-vv) adds the commands executed by external tools.
	Debug Verbosity = 2
	// Trace (-vvv) adds external tool redirection details on top of Debug.
	Trace Verbosity = 3
)

// ParseVerbosity converts the CLI's -v count and -q flag into a level.
func ParseVerbosity(count int, quiet bool) Verbosity {
	if quiet {
		return Quiet
	}
	if count < 0 {
		count = 0
	}
	if count > int(Trace) {
		count = int(Trace)
	}
	return Verbosity(count)
}
