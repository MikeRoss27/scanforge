package auth

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// AuthConfig stores API keys by provider
type AuthConfig struct {
	Providers map[string]map[string]string `yaml:"providers"`
}

// DefaultPath returns the path to the user's auth configuration file
func DefaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".scanforge", "auth.yaml"), nil
}

// Load reads the auth configuration
func Load() (*AuthConfig, error) {
	path, err := DefaultPath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &AuthConfig{Providers: make(map[string]map[string]string)}, nil
		}
		return nil, err
	}

	var cfg AuthConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	if cfg.Providers == nil {
		cfg.Providers = make(map[string]map[string]string)
	}
	return &cfg, nil
}

// Save writes the auth configuration
func (c *AuthConfig) Save() error {
	path, err := DefaultPath()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

// SetKey sets an API key for a provider
func (c *AuthConfig) SetKey(provider, key string) {
	if c.Providers[provider] == nil {
		c.Providers[provider] = make(map[string]string)
	}
	c.Providers[provider]["api_key"] = key
}

// Sync generates tool-specific configurations using the stored keys
func (c *AuthConfig) Sync() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	// 1. Sync Subfinder (provider-config.yaml)
	subfinderDir := filepath.Join(home, ".config", "subfinder")
	if err := os.MkdirAll(subfinderDir, 0755); err != nil {
		return err
	}
	
	// Create provider config map based on available keys
	subfinderConfig := make(map[string][]string)
	for provider, keys := range c.Providers {
		if key, ok := keys["api_key"]; ok {
			subfinderConfig[provider] = []string{key}
		}
	}

	if len(subfinderConfig) > 0 {
		data, err := yaml.Marshal(subfinderConfig)
		if err != nil {
			return err
		}
		subfinderPath := filepath.Join(subfinderDir, "provider-config.yaml")
		if err := os.WriteFile(subfinderPath, data, 0600); err != nil {
			return err
		}
		fmt.Println("Synced subfinder configuration:", subfinderPath)
	}

	// Future integrations: Nuclei, Wappalyzer, etc.
	
	return nil
}
