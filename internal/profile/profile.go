// Package profile resolves named scan profiles and presets to module lists.
package profile

import (
	"fmt"
	"sort"
)

var builtins = map[string][]string{
	"safe": {
		"subfinder",
		"dnsx",
		"httpx",
		"tlsx",
	},
	"recon": {
		"subfinder",
		"dnsbrute",
		"gau",
		"dnsx",
		"httpx",
		"tlsx",
	},
	"passive": {
		"subfinder",
		"dnsx",
		"httpx",
	},
	"web": {
		"subfinder",
		"dnsbrute",
		"dnsx",
		"httpx",
		"whatweb",
		"wafw00f",
		"katana",
		"jssecrets",
		"dbdetect",
		"dbenum",
		"jsverify",
		"attacksurface",
		"techcve",
		"httpcheck",
		"payloadgen",
		"screenshot",
		"nuclei",
	},
	"ports": {
		"subfinder",
		"dnsx",
		"naabu",
		"nmap",
	},
	"vuln": {
		"subfinder",
		"dnsbrute",
		"dnsx",
		"httpx",
		"tlsx",
		"katana",
		"jssecrets",
		"dbdetect",
		"dbenum",
		"attacksurface",
		"techcve",
		"nuclei",
	},
	"deep": {
		"subfinder",
		"dnsbrute",
		"gau",
		"dnsx",
		"httpx",
		"naabu",
		"nmap",
		"tlsx",
		"whatweb",
		"wafw00f",
		"katana",
		"jssecrets",
		"dbdetect",
		"dbenum",
		"jsverify",
		"attacksurface",
		"techcve",
		"httpcheck",
		"payloadgen",
		"screenshot",
		"ffuf",
		"nuclei",
	},
	"full": {
		"subfinder",
		"dnsbrute",
		"gau",
		"dnsx",
		"httpx",
		"naabu",
		"nmap",
		"whatweb",
		"wafw00f",
		"katana",
		"jssecrets",
		"dbdetect",
		"dbenum",
		"jsverify",
		"attacksurface",
		"techcve",
		"httpcheck",
		"payloadgen",
		"screenshot",
		"ffuf",
		"nuclei",
		"tlsx",
	},
	// wp is the WordPress engagement chain: recon + core/plugin/theme
	// fingerprinting, CVE correlation, exposure checks and report.
	// wpbrute (opt-in only) is deliberately NOT part of the preset.
	// "wordpress" is accepted as an alias of "wp".
	"wp": {
		"subfinder",
		"dnsbrute",
		"dnsx",
		"httpx",
		"whatweb",
		"wpdetect",
		"wpplugins",
		"wpthemes",
		"wpusers",
		"wpexposure",
		"wpxmlrpc",
		"wpcve",
		"techcve",
		"httpcheck",
		"nuclei",
		"screenshot",
		"attacksurface",
	},
	"wordpress": {
		"subfinder",
		"dnsbrute",
		"dnsx",
		"httpx",
		"whatweb",
		"wpdetect",
		"wpplugins",
		"wpthemes",
		"wpusers",
		"wpexposure",
		"wpxmlrpc",
		"wpcve",
		"techcve",
		"httpcheck",
		"nuclei",
		"screenshot",
		"attacksurface",
	},
}

func Resolve(name string, overrides map[string][]string) ([]string, error) {
	if overrides != nil {
		if modules, ok := overrides[name]; ok {
			return modules, nil
		}
	}

	if modules, ok := builtins[name]; ok {
		return modules, nil
	}

	return nil, fmt.Errorf("unknown profile %q", name)
}

func Names() []string {
	names := make([]string, 0, len(builtins))
	for k := range builtins {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}
