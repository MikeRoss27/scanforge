package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/MikeRoss27/scanforge/internal/vulnintel"
	"github.com/spf13/cobra"
)

// newIntelClient builds the feed client for `intel update`; tests replace it.
var newIntelClient = func() *vulnintel.Client {
	return &vulnintel.Client{NVDKey: vulnintel.NVDKeyFromEnv(os.Getenv)}
}

// NewIntelCommand groups the vulnerability intelligence cache commands.
// `update` is the only place scanforge reaches out to the intel feeds.
func NewIntelCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "intel",
		GroupID: groupMaintenance,
		Short:   "Manage the local vulnerability intelligence cache (NVD, KEV, EPSS)",
		Long: `Manage the local vulnerability intelligence cache used by techcve.

Feeds are downloaded ONLY by 'intel update'; scans never touch the network for
intel and use the cache in offline mode. Set SCANFORGE_NVD_API_KEY (or
NVD_API_KEY) for a higher NVD rate limit. Cache directory: SCANFORGE_INTEL_DIR
or ~/.cache/scanforge/vulnintel.`,
	}
	cmd.AddCommand(newIntelUpdateCommand(), newIntelStatusCommand())
	return cmd
}

func newIntelUpdateCommand() *cobra.Command {
	var sources []string
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Download and cache the intel feeds (network access)",
		Example: `  scanforge intel update
  scanforge intel update --source kev --source epss`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := vulnintel.OpenDefault()
			if err != nil {
				return err
			}
			client := newIntelClient()
			out := cmd.OutOrStdout()
			client.Progress = func(format string, a ...any) { _, _ = fmt.Fprintf(out, "  "+format+"\n", a...) }
			if client.NVDKey == "" {
				_, _ = fmt.Fprintln(out, "No NVD API key set: using the slow public rate limit (a full NVD download takes ~15 minutes).")
			}
			updated, err := vulnintel.Update(cmd.Context(), store, client, sources)
			for _, sm := range updated {
				_, _ = fmt.Fprintf(out, "%s: %d records (feed %s) -> %s\n", sm.Source, sm.Records, orDash(sm.FeedVersion), store.Dir)
			}
			return err
		},
	}
	cmd.Flags().StringSliceVar(&sources, "source", nil, "Only update this source: nvd, kev or epss (repeatable; default all)")
	return cmd
}

func newIntelStatusCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show what the local intel cache contains (offline)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := vulnintel.OpenDefault()
			if err != nil {
				return err
			}
			meta, err := store.ReadMeta()
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			_, _ = fmt.Fprintf(out, "Cache: %s\n", store.Dir)
			for _, name := range vulnintel.AllSources {
				sm, ok := meta.Sources[name]
				if !ok {
					_, _ = fmt.Fprintf(out, "  %-5s not downloaded (run: scanforge intel update --source %s)\n", name, name)
					continue
				}
				_, _ = fmt.Fprintf(out, "  %-5s %8d records  fetched %s (%s ago)  feed %s\n", name, sm.Records,
					sm.FetchedAt.Format(time.RFC3339), time.Since(sm.FetchedAt).Round(time.Minute), orDash(sm.FeedVersion))
			}
			if !store.HasData() {
				_, _ = fmt.Fprintln(out, "Cache empty: techcve uses its bundled dataset only.")
			}
			return nil
		},
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
