// Package dependencies describes external runtime tools in one place for
// profile-aware diagnostics. Installation scripts remain platform-native, but
// their tool list is validated against this catalog in CI.
package dependencies

import (
	"os"
	"runtime"
	"strings"
)

// PinnedVersions is populated from .tools-version through build ldflags.
// Local development builds may leave it empty; version checks then remain
// informational instead of pretending to know an expected version.
var PinnedVersions string

type Dependency struct {
	Name       string
	Binary     string
	Modules    []string
	Optional   bool
	VersionKey string
	GoPackage  string
	Compare    bool
}

var catalog = []Dependency{
	{Name: "subfinder", Binary: "subfinder", Modules: []string{"subfinder"}, VersionKey: "SUBFINDER_VERSION", GoPackage: "github.com/projectdiscovery/subfinder/v2/cmd/subfinder", Compare: true},
	{Name: "shuffledns", Binary: "shuffledns", Modules: []string{"dnsbrute"}, VersionKey: "SHUFFLEDNS_VERSION", GoPackage: "github.com/projectdiscovery/shuffledns/cmd/shuffledns", Compare: true},
	{Name: "massdns", Binary: "massdns", Modules: []string{"dnsbrute"}},
	{Name: "dnsx", Binary: "dnsx", Modules: []string{"dnsx"}, VersionKey: "DNSX_VERSION", GoPackage: "github.com/projectdiscovery/dnsx/cmd/dnsx", Compare: true},
	{Name: "httpx", Binary: "httpx", Modules: []string{"httpx", "screenshot"}, VersionKey: "HTTPX_VERSION", GoPackage: "github.com/projectdiscovery/httpx/cmd/httpx", Compare: true},
	{Name: "naabu", Binary: "naabu", Modules: []string{"naabu"}, VersionKey: "NAABU_VERSION", GoPackage: "github.com/projectdiscovery/naabu/v2/cmd/naabu", Compare: true},
	{Name: "nmap", Binary: "nmap", Modules: []string{"nmap"}},
	{Name: "whatweb", Binary: "whatweb", Modules: []string{"whatweb"}},
	{Name: "wafw00f", Binary: "wafw00f", Modules: []string{"wafw00f"}, VersionKey: "WAFW00F_VERSION", Compare: true},
	{Name: "katana", Binary: "katana", Modules: []string{"katana"}, VersionKey: "KATANA_VERSION", GoPackage: "github.com/projectdiscovery/katana/cmd/katana", Compare: true},
	{Name: "chromium", Binary: "chromium", Modules: []string{"jsverify"}, Optional: true},
	{Name: "ffuf", Binary: "ffuf", Modules: []string{"ffuf"}, VersionKey: "FFUF_VERSION", GoPackage: "github.com/ffuf/ffuf/v2", Compare: true},
	{Name: "nuclei", Binary: "nuclei", Modules: []string{"nuclei"}, VersionKey: "NUCLEI_VERSION", GoPackage: "github.com/projectdiscovery/nuclei/v3/cmd/nuclei", Compare: true},
	{Name: "gau", Binary: "gau", Modules: []string{"gau"}, VersionKey: "GAU_VERSION", GoPackage: "github.com/lc/gau/v2/cmd/gau", Compare: true},
	{Name: "tlsx", Binary: "tlsx", Modules: []string{"tlsx"}, VersionKey: "TLSX_VERSION", GoPackage: "github.com/projectdiscovery/tlsx/cmd/tlsx", Compare: true},
}

var DNSWordlistCandidates = []string{
	"/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
	"/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
	"/usr/share/seclists/Discovery/DNS/namelist.txt",
	"/opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt",
	"/usr/share/wordlists/amass/subdomains.lst",
	"/usr/share/scanforge/wordlists/subdomains-top1million-5000.txt",
}

func DNSWordlistPaths() []string {
	paths := make([]string, 0, len(DNSWordlistCandidates)+2)
	if explicit := os.Getenv("SCANFORGE_DNS_WORDLIST"); explicit != "" {
		paths = append(paths, explicit)
	}
	if runtime.GOOS == "windows" {
		if localAppData := os.Getenv("LOCALAPPDATA"); localAppData != "" {
			paths = append(paths, localAppData+`\scanforge\wordlists\subdomains-top1million-5000.txt`)
		}
	} else if home, err := os.UserHomeDir(); err == nil {
		dataHome := os.Getenv("XDG_DATA_HOME")
		if dataHome == "" {
			dataHome = home + "/.local/share"
		}
		paths = append(paths, dataHome+"/scanforge/wordlists/subdomains-top1million-5000.txt")
	}
	return append(paths, DNSWordlistCandidates...)
}

func ForModules(modules []string) []Dependency {
	selected := make(map[string]bool, len(modules))
	for _, module := range modules {
		selected[module] = true
	}
	var result []Dependency
	for _, dependency := range catalog {
		for _, module := range dependency.Modules {
			if selected[module] {
				result = append(result, dependency)
				break
			}
		}
	}
	return result
}

func ExpectedVersion(key string) string {
	for _, entry := range strings.Split(PinnedVersions, ",") {
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) == 2 && parts[0] == key {
			return strings.TrimPrefix(parts[1], "v")
		}
	}
	return ""
}

func InstallHint(dependency Dependency) string {
	version := ExpectedVersion(dependency.VersionKey)
	wafw00fSpec := "wafw00f"
	if version != "" {
		wafw00fSpec += "==" + version
	}
	if dependency.GoPackage != "" {
		if version == "" {
			return "go install " + dependency.GoPackage + "@<version from .tools-version>"
		}
		return "go install " + dependency.GoPackage + "@v" + version
	}

	switch runtime.GOOS {
	case "darwin":
		switch dependency.Name {
		case "nmap", "massdns":
			return "brew install " + dependency.Name
		case "wafw00f":
			return "brew install pipx && pipx install " + wafw00fSpec
		case "chromium":
			return "install Google Chrome/Chromium and set tools.chromium if it is not on PATH"
		case "whatweb":
			return "install WhatWeb from upstream, or use Docker"
		}
	case "windows":
		switch dependency.Name {
		case "nmap":
			return "use the official Nmap Windows installer"
		case "wafw00f":
			return "install pipx, then run: pipx install " + wafw00fSpec
		case "whatweb", "massdns":
			return "use WSL/Docker or install the upstream project manually"
		case "chromium":
			return "install Chrome/Chromium and configure tools.chromium"
		}
	default:
		if _, err := os.Stat("/usr/bin/pacman"); err == nil {
			switch dependency.Name {
			case "nmap", "chromium":
				return "sudo pacman -S --needed " + dependency.Name
			case "wafw00f":
				return "sudo pacman -S --needed python-pipx && pipx install " + wafw00fSpec
			case "whatweb":
				return "not in official Arch repos; review the AUR PKGBUILD, install upstream manually, or use Docker"
			case "massdns":
				return "rerun install.sh --full (verified upstream build); an AUR package also exists"
			}
		} else {
			switch dependency.Name {
			case "nmap", "whatweb", "chromium":
				return "sudo apt-get install " + dependency.Name + " (when available on this release)"
			case "wafw00f":
				return "sudo apt-get install pipx && pipx install " + wafw00fSpec
			case "massdns":
				return "rerun install.sh --full for the verified upstream build"
			}
		}
	}
	return "install it with the platform package manager or from upstream"
}
