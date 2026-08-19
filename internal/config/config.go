// Package config loads scanforge.yaml and resolves tool paths and profiles.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/MikeRoss27/scanforge/internal/profile"
	"gopkg.in/yaml.v3"
)

type Config struct {
	ConfigVersion  int                 `yaml:"config_version"`
	Workspace      string              `yaml:"workspace"`
	DefaultProfile string              `yaml:"default_profile"`
	DefaultScope   string              `yaml:"default_scope"`
	Tools          Tools               `yaml:"tools"`
	Profiles       map[string][]string `yaml:"profiles"`
	// ModuleTimeouts bounds how long a module may run before it is killed,
	// keyed by module name with Go duration values (e.g. "30m", "1h30m").
	// Zero (unset) means the module's own default applies.
	ModuleTimeouts map[string]time.Duration `yaml:"module_timeouts"`
	Webhook        Webhook                  `yaml:"webhook"`
}

// Webhook holds the end-of-run notification endpoint. The payload is a
// generic JSON document with a "text" field, so Slack, Discord and Teams
// webhook receivers all get a readable message.
type Webhook struct {
	URL string `yaml:"url"`
}

type Tools struct {
	Subfinder  string `yaml:"subfinder"`
	Dnsx       string `yaml:"dnsx"`
	Httpx      string `yaml:"httpx"`
	Naabu      string `yaml:"naabu"`
	Nmap       string `yaml:"nmap"`
	Whatweb    string `yaml:"whatweb"`
	Wafw00f    string `yaml:"wafw00f"`
	Katana     string `yaml:"katana"`
	Ffuf       string `yaml:"ffuf"`
	Nuclei     string `yaml:"nuclei"`
	Gau        string `yaml:"gau"`
	Tlsx       string `yaml:"tlsx"`
	Shuffledns string `yaml:"shuffledns"`
	Chromium   string `yaml:"chromium"`
}

func ResolvePath(explicitPath string) string {
	if explicitPath != "" {
		return explicitPath
	}

	if envPath := os.Getenv("SCANFORGE_CONFIG"); envPath != "" {
		return envPath
	}

	return DefaultConfigFile
}

func Load(path string) (*Config, error) {
	cfg := Default()

	if path == "" {
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, fmt.Errorf("unable to read config file %q: %w", path, err)
	}

	parsed := Default()
	if err := yaml.Unmarshal(data, parsed); err != nil {
		return nil, fmt.Errorf("unable to parse config file %q: %w", path, err)
	}

	mergeDefaults(cfg, parsed)
	return parsed, nil
}

func LoadResolved(explicitPath string) (*Config, string, error) {
	path := ResolvePath(explicitPath)
	cfg, err := Load(path)
	if err != nil {
		return nil, path, err
	}
	return cfg, path, nil
}

func (c *Config) ToolPath(name string) string {
	switch name {
	case "subfinder":
		if c.Tools.Subfinder != "" {
			return c.Tools.Subfinder
		}
	case "dnsx":
		if c.Tools.Dnsx != "" {
			return c.Tools.Dnsx
		}
	case "httpx":
		if c.Tools.Httpx != "" {
			return c.Tools.Httpx
		}
	case "naabu":
		if c.Tools.Naabu != "" {
			return c.Tools.Naabu
		}
	case "nmap":
		if c.Tools.Nmap != "" {
			return c.Tools.Nmap
		}
	case "whatweb":
		if c.Tools.Whatweb != "" {
			return c.Tools.Whatweb
		}
	case "wafw00f":
		if c.Tools.Wafw00f != "" {
			return c.Tools.Wafw00f
		}
	case "katana":
		if c.Tools.Katana != "" {
			return c.Tools.Katana
		}
	case "ffuf":
		if c.Tools.Ffuf != "" {
			return c.Tools.Ffuf
		}
	case "nuclei":
		if c.Tools.Nuclei != "" {
			return c.Tools.Nuclei
		}
	case "gau":
		if c.Tools.Gau != "" {
			return c.Tools.Gau
		}
	case "tlsx":
		if c.Tools.Tlsx != "" {
			return c.Tools.Tlsx
		}
	case "shuffledns":
		if c.Tools.Shuffledns != "" {
			return c.Tools.Shuffledns
		}
	case "chromium":
		if c.Tools.Chromium != "" {
			return c.Tools.Chromium
		}
	}

	return name
}

func (c *Config) ProfileModules(profileName string) ([]string, error) {
	return profile.Resolve(profileName, c.Profiles)
}

func (c *Config) YAMLTemplate() string {
	return fmt.Sprintf(`config_version: %d
workspace: %s
default_profile: %s
default_scope: %s

tools:
  subfinder: subfinder
  dnsx: dnsx
  httpx: httpx
  naabu: naabu
  nmap: nmap
  whatweb: whatweb
  wafw00f: wafw00f
  katana: katana
  ffuf: ffuf
  nuclei: nuclei
  gau: gau
  tlsx: tlsx
  chromium: chromium

# overrides for built-in profiles (safe, recon, web, ports, vuln, deep, full)
# profiles:
#   passive:
#     - subfinder
#     - httpx

# per-module time limits (Go durations); a module exceeding its limit is
# killed and reported as failed, and its dependents are skipped
# module_timeouts:
#   nuclei: 45m
#   katana: 20m
`, DefaultConfigVersion, DefaultWorkspace, DefaultProfile, DefaultScope)
}

func mergeDefaults(base, parsed *Config) {
	if parsed.ConfigVersion == 0 {
		parsed.ConfigVersion = base.ConfigVersion
	}
	if parsed.Workspace == "" {
		parsed.Workspace = base.Workspace
	}
	if parsed.DefaultProfile == "" {
		parsed.DefaultProfile = base.DefaultProfile
	}
	if parsed.DefaultScope == "" {
		parsed.DefaultScope = base.DefaultScope
	}
	if parsed.Tools.Subfinder == "" {
		parsed.Tools.Subfinder = base.Tools.Subfinder
	}
	if parsed.Tools.Dnsx == "" {
		parsed.Tools.Dnsx = base.Tools.Dnsx
	}
	if parsed.Tools.Httpx == "" {
		parsed.Tools.Httpx = base.Tools.Httpx
	}
	if parsed.Tools.Naabu == "" {
		parsed.Tools.Naabu = base.Tools.Naabu
	}
	if parsed.Tools.Nmap == "" {
		parsed.Tools.Nmap = base.Tools.Nmap
	}
	if parsed.Tools.Whatweb == "" {
		parsed.Tools.Whatweb = base.Tools.Whatweb
	}
	if parsed.Tools.Wafw00f == "" {
		parsed.Tools.Wafw00f = base.Tools.Wafw00f
	}
	if parsed.Tools.Katana == "" {
		parsed.Tools.Katana = base.Tools.Katana
	}
	if parsed.Tools.Ffuf == "" {
		parsed.Tools.Ffuf = base.Tools.Ffuf
	}
	if parsed.Tools.Nuclei == "" {
		parsed.Tools.Nuclei = base.Tools.Nuclei
	}
	if parsed.Tools.Gau == "" {
		parsed.Tools.Gau = base.Tools.Gau
	}
	if parsed.Tools.Tlsx == "" {
		parsed.Tools.Tlsx = base.Tools.Tlsx
	}
	if parsed.Tools.Shuffledns == "" {
		parsed.Tools.Shuffledns = base.Tools.Shuffledns
	}
	if len(parsed.Profiles) == 0 {
		parsed.Profiles = base.Profiles
	}
}

func WorkspaceDir(cfg *Config) string {
	if cfg == nil || cfg.Workspace == "" {
		return DefaultWorkspace
	}
	return filepath.Clean(cfg.Workspace)
}
