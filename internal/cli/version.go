package cli

import (
	"fmt"
	"runtime"

	"github.com/MikeRoss27/scanforge/internal/version"
	"github.com/spf13/cobra"
)

func NewVersionCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print ScanForge version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("ScanForge", version.Version)
			fmt.Println("Commit:", version.Commit)
			fmt.Println("Date:", version.Date)
			fmt.Println("Go:", runtime.Version())
		},
	}

	return cmd
}
