package app

import (
	"encoding/json"
	"testing"
)

func TestPersistParamsKeepsRecursiveSettings(t *testing.T) {
	params, err := persistParams(RunOptions{Recursive: true, RecursiveDepth: 3, RecursiveBudget: 42}, []string{"httpx"})
	if err != nil {
		t.Fatal(err)
	}
	var got persistedOptions
	if err := json.Unmarshal(params.Options, &got); err != nil {
		t.Fatal(err)
	}
	if !got.Recursive || got.RecursiveDepth != 3 || got.RecursiveBudget != 42 {
		t.Fatalf("recursive settings not persisted for resume: %+v", got)
	}
}
