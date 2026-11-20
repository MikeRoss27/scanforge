package app

// WordPress chain injected by --wp: detection first, then fingerprinting of
// plugins/themes, user enumeration, exposure checks, XML-RPC and CVE
// correlation. These modules are no-ops on hosts that do not identify as
// WordPress, so appending them to any profile is safe. wpbrute is appended
// only when the operator passes --wp-bruteforce.
var wordPressChain = []string{
	"wpdetect",
	"wpplugins",
	"wpthemes",
	"wpusers",
	"wpexposure",
	"wpxmlrpc",
	"wpcve",
	"attacksurface",
}

// applyWordPress appends the WordPress engagement chain to a module list when
// the --wp flag is set (or when the selected profile is the wp preset itself,
// which resolves to the same list). Existing entries win so a profile can
// tune the chain (e.g. drop wpusers) and the result stays deduplicated.
func applyWordPress(names []string, wp bool, bruteforce bool) []string {
	if !wp {
		// The wp preset already resolves to the chain via Profiles; nothing
		// to append. wpbrute (opt-in) can still be layered on with --wp-bruteforce.
		if !bruteforce {
			return names
		}
		return appendIfMissing(names, []string{"wpbrute"})
	}
	chain := append([]string{}, wordPressChain...)
	if bruteforce {
		chain = append(chain, "wpbrute")
	}
	return appendIfMissing(names, chain)
}

func appendIfMissing(names, wanted []string) []string {
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		seen[name] = struct{}{}
	}
	out := append([]string{}, names...)
	for _, name := range wanted {
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	return out
}
