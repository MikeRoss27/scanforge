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
		"ctlogs",
		"dnsbrute",
		"dnspermute",
		"alterx",
		"gau",
		"dnsx",
		"asnmap",
		"uncover",
		"httpx",
		"tlsx",
	},
	"passive": {
		"subfinder",
		"ctlogs",
		"dnsx",
		"httpx",
	},
	"web": {
		"subfinder",
		"ctlogs",
		"dnsbrute",
		"dnspermute",
		"alterx",
		"dnsx",
		"asnmap",
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
		"dnspermute",
		"alterx",
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
		"ctlogs",
		"dnsbrute",
		"dnspermute",
		"alterx",
		"gau",
		"dnsx",
		"asnmap",
		"uncover",
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
		"ctlogs",
		"dnsbrute",
		"dnspermute",
		"alterx",
		"gau",
		"dnsx",
		"asnmap",
		"uncover",
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
		"dnspermute",
		"alterx",
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
		"dnspermute",
		"alterx",
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
