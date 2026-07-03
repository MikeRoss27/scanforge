package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ConfigVersion  int                 `yaml:"config_version"`
	Workspace      string              `yaml:"workspace"`
	DefaultProfile string              `yaml:"default_profile"`
	DefaultScope   string              `yaml:"default_scope"`
	Tools          Tools               `yaml:"tools"`
	Profiles       map[string][]string `yaml:"profiles"`
}

type Tools struct {
	Subfinder string `yaml:"subfinder"`
	Httpx     string `yaml:"httpx"`
	Nuclei    string `yaml:"nuclei"`
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

	if _, err := os.Stat(path); err == nil {
		return cfg, path, nil
	}

	return cfg, path, nil
}

func (c *Config) ToolPath(name string) string {
	switch name {
	case "subfinder":
		if c.Tools.Subfinder != "" {
			return c.Tools.Subfinder
		}
	case "httpx":
		if c.Tools.Httpx != "" {
			return c.Tools.Httpx
		}
	case "nuclei":
		if c.Tools.Nuclei != "" {
			return c.Tools.Nuclei
		}
	}

	return name
}

func (c *Config) ProfileModules(profile string) ([]string, error) {
	modules, ok := c.Profiles[profile]
	if !ok || len(modules) == 0 {
		return nil, fmt.Errorf("unknown profile %q", profile)
	}

	return modules, nil
}

func (c *Config) YAMLTemplate() string {
	return fmt.Sprintf(`config_version: %d
workspace: %s
default_profile: %s
default_scope: %s

tools:
  subfinder: subfinder
  httpx: httpx
  nuclei: nuclei

profiles:
  passive:
    - subfinder
    - httpx
  web:
    - subfinder
    - httpx
    - nuclei
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
	if parsed.Tools.Httpx == "" {
		parsed.Tools.Httpx = base.Tools.Httpx
	}
	if parsed.Tools.Nuclei == "" {
		parsed.Tools.Nuclei = base.Tools.Nuclei
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
