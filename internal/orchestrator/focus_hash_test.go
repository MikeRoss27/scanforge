package orchestrator

import (
	"reflect"
	"testing"
)

type digestFocus string

func (digestFocus) Keep(string) bool { return true }
func (d digestFocus) Digest() string { return string(d) }

func TestModuleParamsFoldIncrementalFocusIntoFocusModulesOnly(t *testing.T) {
	plain := Options{}
	focused := Options{InputFocus: digestFocus("A")}
	other := Options{InputFocus: digestFocus("B")}

	for _, name := range []string{"nuclei", "ffuf", "katana", "jssecrets"} {
		if reflect.DeepEqual(moduleParams(name, plain), moduleParams(name, focused)) {
			t.Errorf("%s: params must differ with an incremental focus", name)
		}
		if reflect.DeepEqual(moduleParams(name, focused), moduleParams(name, other)) {
			t.Errorf("%s: params must differ between two focus digests", name)
		}
	}
	for _, name := range []string{"httpx", "dnsx", "nmap"} {
		if !reflect.DeepEqual(moduleParams(name, plain), moduleParams(name, focused)) {
			t.Errorf("%s: params must not depend on the focus", name)
		}
	}
}
