// Package payloadgen tech registry maps a technology keyword to well-known paths
// worth probing. The map is intentionally small and safe to probe; users can
// extend it via an external JSON file without recompiling.
package payloadgen

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// defaultTechEndpoints is the embedded fallback. Keys are lower-cased.
var defaultTechEndpoints = map[string][]string{
	"wordpress":  {"wp-login.php", "wp-admin/", "wp-json/wp/v2/users", "xmlrpc.php", "wp-content/debug.log"},
	"drupal":     {"CHANGELOG.txt", "core/install.php", "admin/", "user/login", "update.php"},
	"joomla":     {"administrator/", "configuration.php~", "index.php?option=com_users"},
	"django":     {"admin/", "api-auth/", "graphql", "media/", "static/"},
	"rails":      {"rails/info", "assets/application.js", "admin/", "graphql"},
	"laravel":    {"_ignition/health-check", "_ignition/execute-solution", "api/", "storage/logs/laravel.log"},
	"spring":     {"actuator", "actuator/health", "actuator/env", "actuator/beans", "swagger-ui/", "v3/api-docs"},
	"grafana":    {"api/health", "api/dashboards", "login"},
	"kibana":     {"api/status", "app/discover"},
	"jenkins":    {"script", "api/json", "login", "cli"},
	"phpmyadmin": {"index.php"},
	"gitlab":     {"api/v4/projects", "users/sign_in", ".well-known/security.txt"},
	"confluence": {"/rest/api/content", "login.action"},
	"jira":       {"rest/api/2/serverInfo", "secure/Dashboard.jspa", "browse"},
	// Aliases / common variations that whatweb sometimes returns under a different name.
	"tomcat":  {"manager/html", "host-manager/html"},
	"apache":  {"server-status", "server-info"},
	"nginx":   {"nginx_status"},
	"next.js": {"_next/static/", "_next/data/"},
	"nextjs":  {"_next/static/", "_next/data/"},
	"react":   {"static/js/main.js"},
	"angular": {"main.js", "runtime.js"},
	"vue":     {"js/app.js"},
}

// techEndpoints is an alias kept for backward compatibility with existing tests.
// New code should use defaultTechEndpoints or getTechRegistry().
var techEndpoints = defaultTechEndpoints

// techAliases normalizes composite whatweb names to canonical keys.
// e.g. "Apache Tomcat" -> "tomcat", "WordPress" -> "wordpress" (handled by ToLower + trim).
var techAliases = map[string]string{
	"springboot":  "spring",
	"spring_boot": "spring",
	"wp":          "wordpress",
}

// getTechRegistry returns the effective registry: defaults merged with an
// optional user file. The user file, if present, is merged — it can add new
// techs or append to existing ones — so a user never has to duplicate the
// defaults. Missing file is not an error.
func getTechRegistry() map[string][]string {
	// Deep copy defaults so callers can mutate without affecting the global.
	merged := make(map[string][]string, len(defaultTechEndpoints))
	for k, v := range defaultTechEndpoints {
		cp := make([]string, len(v))
		copy(cp, v)
		merged[k] = cp
	}

	// Lookup order: $SCANFORGE_TECH_ENDPOINTS > $XDG_CONFIG_HOME/scanforge/tech-endpoints.json
	//               > ~/.config/scanforge/tech-endpoints.json
	candidates := []string{}
	if p := os.Getenv("SCANFORGE_TECH_ENDPOINTS"); p != "" {
		candidates = append(candidates, p)
	}
	if dir, err := os.UserConfigDir(); err == nil {
		candidates = append(candidates, filepath.Join(dir, "scanforge", "tech-endpoints.json"))
	}
	// Fallback to explicit home config (UserConfigDir already covers it on linux, but keep for compat)
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(home, ".config", "scanforge", "tech-endpoints.json"))
	}

	for _, path := range candidates {
		if path == "" {
			continue
		}
		if data, err := os.ReadFile(path); err == nil {
			var extra map[string][]string
			if err := json.Unmarshal(data, &extra); err != nil {
				// Corrupt user file — keep defaults and surface via warning in caller.
				continue
			}
			for k, v := range extra {
				norm := normalizeTechKey(k)
				if existing, ok := merged[norm]; ok {
					merged[norm] = dedupe(append(existing, v...))
				} else {
					merged[norm] = dedupe(v)
				}
			}
			break // first found file wins
		}
	}
	return merged
}

// normalizeTechKey lower-cases and trims a registry key.
func normalizeTechKey(raw string) string {
	k := strings.ToLower(strings.TrimSpace(raw))
	if alias, ok := techAliases[k]; ok {
		return alias
	}
	return k
}

// normalizeTechToken extracts a canonical tech name from a whatweb field.
// whatweb fields look like "WordPress[6.3]", "Apache/2.4.41", "nginx[1.22.0]" or
// "jQuery[3.6.0]". We handle:
//   - bracket version: "WordPress[6.3]" -> "wordpress"
//   - slash version:   "Apache/2.4.41"   -> "apache"
//   - plain:           "nginx"           -> "nginx"
func normalizeTechToken(field string) string {
	field = strings.TrimSpace(field)
	if field == "" {
		return ""
	}
	// Strip bracket portion: "WordPress[6.3]" -> "WordPress"
	if idx := strings.IndexByte(field, '['); idx > 0 {
		field = field[:idx]
	}
	// Strip slash version: "Apache/2.4.41" -> "Apache"
	if idx := strings.IndexByte(field, '/'); idx > 0 {
		field = field[:idx]
	}
	field = strings.ToLower(strings.TrimSpace(field))
	// Remove non-alphanum except '.' '-' '_'
	// Keep '.' for "next.js" etc. Caller will try both original and alias.
	clean := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' {
			return r
		}
		// e.g. "ApacheTomcat" keeps as is (lowered)
		return -1
	}, field)
	if alias, ok := techAliases[clean]; ok {
		return alias
	}
	return clean
}

// lookupTechEndpoints returns the endpoints for a normalized tech, trying
// both the raw normalized token and common aliases. Empty slice if unknown.
func lookupTechEndpoints(registry map[string][]string, token string) []string {
	if v, ok := registry[token]; ok {
		return v
	}
	// Try without dots/dashes: "next.js" vs "nextjs"
	alt := strings.ReplaceAll(strings.ReplaceAll(token, ".", ""), "-", "")
	if v, ok := registry[alt]; ok {
		return v
	}
	return nil
}

// TechRegistryForTest exposes the merged registry for tests.
func TechRegistryForTest() map[string][]string { return getTechRegistry() }

// LoadTechEndpointsFromFile loads a JSON file at path and merges it onto defaults.
// Exported for tests and for future CLI `payloadgen --tech-endpoints` flag.
func LoadTechEndpointsFromFile(path string) (map[string][]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read tech endpoints %q: %w", path, err)
	}
	var extra map[string][]string
	if err := json.Unmarshal(data, &extra); err != nil {
		return nil, fmt.Errorf("parse tech endpoints %q: %w", path, err)
	}
	merged := make(map[string][]string, len(defaultTechEndpoints))
	for k, v := range defaultTechEndpoints {
		cp := make([]string, len(v))
		copy(cp, v)
		merged[strings.ToLower(k)] = cp
	}
	for k, v := range extra {
		norm := normalizeTechKey(k)
		if existing, ok := merged[norm]; ok {
			merged[norm] = dedupe(append(existing, v...))
		} else {
			merged[norm] = dedupe(v)
		}
	}
	return merged, nil
}
