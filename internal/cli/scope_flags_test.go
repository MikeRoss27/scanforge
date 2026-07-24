package cli

import (
	"testing"

	"github.com/MikeRoss27/scanforge/internal/app"
	"github.com/spf13/cobra"
)

func TestRunAndPlanExposeImplicitScopeFlags(t *testing.T) {
	commands := map[string]*cobra.Command{
		"run":  NewRunCommand(app.New("")),
		"plan": NewPlanCommand(app.New("")),
	}
	for name, command := range commands {
		for _, flag := range []string{"scope-mode", "scope-add", "exclude"} {
			if command.Flags().Lookup(flag) == nil {
				t.Errorf("%s command missing --%s", name, flag)
			}
		}
	}
	if commands["run"].Flags().Lookup("confirm-scope") == nil {
		t.Error("run command missing --confirm-scope")
	}
}
