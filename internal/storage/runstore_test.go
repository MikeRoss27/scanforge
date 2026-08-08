package storage

import "testing"

func TestCreateUniqueRunDirectories(t *testing.T) {
	store := NewRunStore(t.TempDir())

	first, err := store.Create("example.com")
	if err != nil {
		t.Fatalf("first Create() error = %v", err)
	}
	second, err := store.Create("example.com")
	if err != nil {
		t.Fatalf("second Create() error = %v", err)
	}

	if first.ID == second.ID {
		t.Fatalf("runs share the same ID %q", first.ID)
	}
	if first.RootDir == second.RootDir {
		t.Fatalf("runs share the same directory %q", first.RootDir)
	}
}

func TestCreateRunDirectoryExists(t *testing.T) {
	store := NewRunStore(t.TempDir())

	run, err := store.Create("example.com")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	_, err = store.Create("example.com")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if run.ID == "" {
		t.Fatal("expected a non-empty run ID")
	}
}
