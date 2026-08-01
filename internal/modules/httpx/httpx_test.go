package httpx

import (
	"reflect"
	"testing"
)

func TestRequiresResolvedHosts(t *testing.T) {
	if got, want := New("").Requires(), []string{"resolved_hosts"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Requires() = %v, want %v", got, want)
	}
}
