package dependencies

import "testing"

func TestForModulesMapsSharedAndTransitiveDependencies(t *testing.T) {
	dependencies := ForModules([]string{"dnsbrute", "screenshot", "jsverify"})
	seen := map[string]Dependency{}
	for _, dependency := range dependencies {
		seen[dependency.Name] = dependency
	}
	for _, name := range []string{"shuffledns", "massdns", "httpx", "chromium"} {
		if _, ok := seen[name]; !ok {
			t.Errorf("missing dependency %s", name)
		}
	}
	if !seen["chromium"].Optional {
		t.Error("chromium should be optional because jsverify degrades gracefully")
	}
}

func TestExpectedVersionUsesInjectedManifest(t *testing.T) {
	previous := PinnedVersions
	PinnedVersions = "SUBFINDER_VERSION=v2.17.0,DNSX_VERSION=v1.3.1"
	t.Cleanup(func() { PinnedVersions = previous })
	if got := ExpectedVersion("SUBFINDER_VERSION"); got != "2.17.0" {
		t.Fatalf("unexpected version: %q", got)
	}
}

// A GoPackage dependency with no pinned version (either .tools-version has
// no entry for it yet, or - gotator's actual case - the upstream module has
// no semver-compatible tag to pin to at all) must fall back to @latest
// instead of printing the unfillable "@<version from .tools-version>"
// placeholder as if it were a real install command.
func TestInstallHintFallsBackToLatestWithoutPinnedVersion(t *testing.T) {
	previous := PinnedVersions
	PinnedVersions = ""
	t.Cleanup(func() { PinnedVersions = previous })

	hint := InstallHint(Dependency{Name: "gotator", GoPackage: "github.com/Josue87/gotator"})
	if want := "go install github.com/Josue87/gotator@latest"; hint != want {
		t.Fatalf("InstallHint() = %q, want %q", hint, want)
	}
}

func TestInstallHintUsesPinnedVersionWhenPresent(t *testing.T) {
	previous := PinnedVersions
	PinnedVersions = "SUBFINDER_VERSION=v2.17.0"
	t.Cleanup(func() { PinnedVersions = previous })

	hint := InstallHint(Dependency{
		Name: "subfinder", GoPackage: "github.com/projectdiscovery/subfinder/v2/cmd/subfinder", VersionKey: "SUBFINDER_VERSION",
	})
	if want := "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.17.0"; hint != want {
		t.Fatalf("InstallHint() = %q, want %q", hint, want)
	}
}
