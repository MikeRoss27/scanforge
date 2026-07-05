package profile

import (
	"fmt"
)

var builtins = map[string][]string{
	"passive": {
		"subfinder",
		"dnsx",
		"httpx",
	},
	"web": {
		"subfinder",
		"dnsx",
		"httpx",
		"whatweb",
		"wafw00f",
		"katana",
		"nuclei",
	},
	"ports": {
		"subfinder",
		"dnsx",
		"naabu",
		"nmap",
	},
	"full": {
		"subfinder",
		"dnsx",
		"httpx",
		"naabu",
		"nmap",
		"whatweb",
		"wafw00f",
		"katana",
		"ffuf",
		"nuclei",
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
	return names
}
