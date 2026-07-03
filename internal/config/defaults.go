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
			Httpx:     "httpx",
			Nuclei:    "nuclei",
		},
		Profiles: map[string][]string{
			"passive": {"subfinder", "httpx"},
			"web":     {"subfinder", "httpx", "nuclei"},
		},
	}
}
