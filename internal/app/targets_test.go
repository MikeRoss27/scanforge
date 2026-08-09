package app

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestReadTargets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.txt")
	content := "# Engagement scope\n\nexample.com\n  api.example.com  \nexample.com\n\n# repeat above\n10.0.0.0/24\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	got, err := ReadTargets(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"example.com", "api.example.com", "10.0.0.0/24"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ReadTargets() = %v, want %v", got, want)
	}
}

func TestReadTargetsEmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(path, []byte("# nothing\n\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadTargets(path); err == nil {
		t.Fatal("empty targets file must fail")
	}
}

func TestExpandTargetsExclusive(t *testing.T) {
	if _, err := expandTargets("", ""); err == nil {
		t.Fatal("no target source must fail")
	}
	if _, err := expandTargets("example.com", "targets.txt"); err == nil {
		t.Fatal("both target sources must fail")
	}
	if got, err := expandTargets("example.com", ""); err != nil || len(got) != 1 || got[0] != "example.com" {
		t.Fatalf("single target: %v %v", got, err)
	}
}

func TestRunMultiTargetDryRunCreatesPerTargetRuns(t *testing.T) {
	root := t.TempDir()
	app := New(writeTestConfig(t, root))
	targetsFile := filepath.Join(root, "targets.txt")
	if err := os.WriteFile(targetsFile, []byte("example.com\napi.example.test\n"), 0644); err != nil {
		t.Fatal(err)
	}

	err := app.Run(context.Background(), RunOptions{
		TargetsFile:  targetsFile,
		Profile:      "passive",
		DryRun:       true,
		ConfirmScope: true,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	for _, target := range []string{"example.com", "api.example.test"} {
		entries, err := os.ReadDir(filepath.Join(root, "runs", target))
		if err != nil {
			t.Fatalf("missing runs/%s: %v", target, err)
		}
		if len(entries) != 1 {
			t.Fatalf("runs/%s has %d runs, want 1", target, len(entries))
		}
		manifest, err := os.ReadFile(filepath.Join(root, "runs", target, entries[0].Name(), "00_meta", "manifest.json"))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(manifest), `"status": "completed"`) {
			t.Fatalf("run for %s not completed: %s", target, manifest)
		}
	}
}

func TestPlanMultiTargetReturnsOneResultPerTarget(t *testing.T) {
	root := t.TempDir()
	app := New(writeTestConfig(t, root))
	targetsFile := filepath.Join(root, "targets.txt")
	if err := os.WriteFile(targetsFile, []byte("example.com\napi.example.test\n"), 0644); err != nil {
		t.Fatal(err)
	}

	plans, err := app.Plan(PlanOptions{TargetsFile: targetsFile, Profile: "passive"})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if len(plans) != 2 {
		t.Fatalf("plan count = %d, want 2", len(plans))
	}
	if plans[0].Target != "example.com" || plans[1].Target != "api.example.test" {
		t.Fatalf("unexpected plan targets: %v, %v", plans[0].Target, plans[1].Target)
	}
}
