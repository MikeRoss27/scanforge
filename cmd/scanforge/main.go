// Command scanforge is the CLI entry point.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/MikeRoss27/scanforge/internal/app"
	"github.com/MikeRoss27/scanforge/internal/cli"
	"github.com/MikeRoss27/scanforge/internal/orchestrator"
)

func main() {
	// SIGINT/SIGTERM cancel the command context so a scan is torn down
	// gracefully (manifest finalized) instead of dying abruptly.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	rootCmd := cli.NewRootCommand()
	rootCmd.SetContext(ctx)

	if err := rootCmd.Execute(); err != nil {
		// A user-initiated abort is not a failure: distinct message and exit
		// code (128 + SIGINT) so scripts can tell them apart.
		if errors.Is(err, orchestrator.ErrRunAborted) || errors.Is(err, context.Canceled) {
			fmt.Fprintln(os.Stderr, "Scan aborted.")
			os.Exit(130)
		}
		var exitCode app.ExitCodeError
		if errors.As(err, &exitCode) {
			os.Exit(exitCode.Code)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
