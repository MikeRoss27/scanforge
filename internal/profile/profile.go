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
