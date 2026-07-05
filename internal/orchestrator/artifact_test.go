package orchestrator

import (
	"testing"
)

func TestRunContextArtifacts(t *testing.T) {
	ctx := NewRunContext("example.com", "passive", false, nil)

	ctx.AddArtifact("subdomains", Artifact{
		Name: "subdomains",
		Type: "text",
		Path: "01_subdomains/subfinder.txt",
	})

	art, ok := ctx.GetArtifact("subdomains")
	if !ok {
		t.Fatal("expected to get artifact")
	}
	if art.Path != "01_subdomains/subfinder.txt" {
		t.Fatalf("unexpected path: %s", art.Path)
	}

	if _, ok := ctx.GetArtifact("missing"); ok {
		t.Fatal("expected missing artifact to return false")
	}

	_, err := ctx.MustArtifact("subdomains")
	if err != nil {
		t.Fatalf("unexpected error from MustArtifact: %v", err)
	}

	_, err = ctx.MustArtifact("missing")
	if err == nil {
		t.Fatal("expected error from MustArtifact for missing artifact")
	}
}
