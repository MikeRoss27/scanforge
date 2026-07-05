package config

const (
	DefaultConfigFile    = "scanforge.yaml"
	DefaultWorkspace     = "runs"
	DefaultProfile       = "passive"
	DefaultScope         = "scope.txt"
	DefaultConfigVersion = 1
)

func Default() *Config {
	return &Config{
		ConfigVersion:  DefaultConfigVersion,
		Workspace:      DefaultWorkspace,
		DefaultProfile: DefaultProfile,
		DefaultScope:   DefaultScope,
		Tools: Tools{
			Subfinder: "subfinder",
			Dnsx:      "dnsx",
			Httpx:     "httpx",
			Naabu:     "naabu",
			Nmap:      "nmap",
			Whatweb:   "whatweb",
			Wafw00f:   "wafw00f",
			Katana:    "katana",
			Ffuf:      "ffuf",
			Nuclei:    "nuclei",
		},
		Profiles: map[string][]string{},
	}
}
