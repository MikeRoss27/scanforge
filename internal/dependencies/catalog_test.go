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
	PinnedVersions = "SUBFINDER_VERSION=v2.15.0,DNSX_VERSION=v1.3.0"
	t.Cleanup(func() { PinnedVersions = previous })
	if got := ExpectedVersion("SUBFINDER_VERSION"); got != "2.15.0" {
		t.Fatalf("unexpected version: %q", got)
	}
}
