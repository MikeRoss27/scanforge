package cli

import (
	"fmt"
	"runtime"

	"github.com/MikeRoss27/scanforge/internal/ui"
	"github.com/MikeRoss27/scanforge/internal/version"
	"github.com/spf13/cobra"
)

func NewVersionCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "version",
		GroupID: groupMaintenance,
		Short:   "Print ScanForge version information",
		Run: func(cmd *cobra.Command, args []string) {
			var body string
			body += fmt.Sprintf("%-10s %s\n", ui.DimBold("VERSION"), ui.Primary(version.Version))
			body += fmt.Sprintf("%-10s %s\n", ui.DimBold("COMMIT"), ui.Dim(version.Commit))
			body += fmt.Sprintf("%-10s %s\n", ui.DimBold("DATE"), ui.Dim(version.Date))
			body += fmt.Sprintf("%-10s %s", ui.DimBold("GO"), ui.Dim(runtime.Version()))
			fmt.Println(ui.PanelWith("🛠 SCANFORGE", body, ui.Accent, ui.Accent))
		},
	}

	return cmd
}
