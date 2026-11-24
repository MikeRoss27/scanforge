package orchestrator

import "testing"

func TestBatchWaveUsesLowestLevel(t *testing.T) {
	levels := map[string]int{"jssecrets": 6, "katana": 5, "techcve": 5}
	if got := batchWave([]string{"jssecrets", "katana"}, levels); got != 5 {
		t.Fatalf("batchWave() = %d, want 5 (lowest level, not the first module's)", got)
	}
	if got := batchWave([]string{"unknown"}, levels); got != 0 {
		t.Fatalf("batchWave(unknown) = %d, want 0", got)
	}
}
