package assets

import (
	"testing"

	"github.com/MikeRoss27/scanforge/internal/report"
	"github.com/MikeRoss27/scanforge/internal/storage"
)

// TestObserveSeesRecursiveAssets: the asset history is fed by the generated
// report, so assets from the 07_recursive follow-ups must be observed.
func TestObserveSeesRecursiveAssets(t *testing.T) {
	rep, err := report.GenerateReport("../report/testdata/evidence_run", &storage.RunManifest{
		Target: "example.com", Profile: "web",
		Outputs: map[string]string{"resolved_hosts": "01_subdomains/resolved.txt"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, o := range Observe(rep) {
		got[o.Type+"|"+o.Value] = true
	}
	for _, want := range []string{
		TypeSubdomain + "|dev.example.com",
		TypeURL + "|https://dev.example.com",
		TypePath + "|https://dev.example.com/api/v1/users",
	} {
		if !got[want] {
			t.Errorf("observation %q missing", want)
		}
	}
	for k := range got {
		if k == TypeSubdomain+"|evil.other.com" || k == TypeSubdomain+"|stale.example.org" {
			t.Errorf("out-of-scope observation %q", k)
		}
	}
}
