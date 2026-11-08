package config

import "time"

const (
	DefaultConfigFile    = "scanforge.yaml"
	DefaultWorkspace     = "runs"
	DefaultProfile       = "passive"
	DefaultScope         = "scope.txt"
	DefaultConfigVersion = 1

	// DefaultAITimeout bounds a single triage generation request.
	DefaultAITimeout = 5 * time.Minute
	// DefaultAITemperature keeps triage output stable and reproducible.
	DefaultAITemperature = 0.1
)

func Default() *Config {
	defaultTemp := DefaultAITemperature
	return &Config{
		ConfigVersion:  DefaultConfigVersion,
		Workspace:      DefaultWorkspace,
		DefaultProfile: DefaultProfile,
		DefaultScope:   DefaultScope,
		Tools: Tools{
			Subfinder:  "subfinder",
			Dnsx:       "dnsx",
			Httpx:      "httpx",
			Naabu:      "naabu",
			Nmap:       "nmap",
			Whatweb:    "whatweb",
			Wafw00f:    "wafw00f",
			Katana:     "katana",
			Ffuf:       "ffuf",
			Nuclei:     "nuclei",
			Gau:        "gau",
			Tlsx:       "tlsx",
			Shuffledns: "shuffledns",
			Chromium:   "chromium",
		},
		Profiles:       map[string][]string{},
		ModuleTimeouts: map[string]time.Duration{},
		AI: AI{
			Timeout:     DefaultAITimeout,
			Temperature: &defaultTemp,
		},
	}
}
