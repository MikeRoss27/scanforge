package benchmark

import "testing"

func TestLabsParsesEveryBundledLab(t *testing.T) {
	labs, err := Labs()
	if err != nil {
		t.Fatalf("Labs() error = %v", err)
	}
	if len(labs) != 4 {
		t.Fatalf("Labs() returned %d labs, want 4: %+v", len(labs), labs)
	}

	wantNames := map[string]bool{
		"firing-range":    false,
		"testphp-vulnweb": false,
		"juice-shop-demo": false,
		"dvwa":            false,
	}
	for _, lab := range labs {
		if lab.Name == "" || lab.Target == "" || lab.Profile == "" || lab.ScopeMode == "" {
			t.Fatalf("lab %+v missing a required field", lab)
		}
		if _, ok := wantNames[lab.Name]; !ok {
			t.Fatalf("unexpected lab name %q", lab.Name)
		}
		wantNames[lab.Name] = true
	}
	for name, seen := range wantNames {
		if !seen {
			t.Fatalf("expected lab %q was not loaded", name)
		}
	}
}

func TestLabsIsSortedByName(t *testing.T) {
	labs, err := Labs()
	if err != nil {
		t.Fatalf("Labs() error = %v", err)
	}
	for i := 1; i < len(labs); i++ {
		if labs[i-1].Name > labs[i].Name {
			t.Fatalf("Labs() not sorted: %q before %q", labs[i-1].Name, labs[i].Name)
		}
	}
}

func TestDVWAIsTheOnlyStrictLab(t *testing.T) {
	labs, err := Labs()
	if err != nil {
		t.Fatalf("Labs() error = %v", err)
	}
	for _, lab := range labs {
		want := lab.Name == "dvwa"
		if lab.Strict != want {
			t.Errorf("lab %q Strict = %v, want %v", lab.Name, lab.Strict, want)
		}
	}
}

func TestDVWAHasSetupInstructions(t *testing.T) {
	lab, err := LabByName("dvwa")
	if err != nil {
		t.Fatalf("LabByName(dvwa) error = %v", err)
	}
	if lab.Setup == "" {
		t.Fatal("dvwa lab has no setup instructions, but it requires a manual docker run")
	}
}

func TestLabByNameUnknown(t *testing.T) {
	_, err := LabByName("does-not-exist")
	if err == nil {
		t.Fatal("expected an error for an unknown lab name")
	}
}

func TestLabByNameFindsEachBundledLab(t *testing.T) {
	for _, name := range []string{"firing-range", "testphp-vulnweb", "juice-shop-demo", "dvwa"} {
		if _, err := LabByName(name); err != nil {
			t.Errorf("LabByName(%q) error = %v", name, err)
		}
	}
}
