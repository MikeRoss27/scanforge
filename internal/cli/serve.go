package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/MikeRoss27/scanforge/internal/active"
	"github.com/MikeRoss27/scanforge/internal/api"
	"github.com/MikeRoss27/scanforge/internal/app"
	"github.com/MikeRoss27/scanforge/internal/auth"
	"github.com/MikeRoss27/scanforge/internal/config"
	"github.com/MikeRoss27/scanforge/internal/mcp"
	"github.com/MikeRoss27/scanforge/internal/runindex"
	"github.com/MikeRoss27/scanforge/internal/version"
	"github.com/spf13/cobra"
)

type serveFlags struct {
	allowActive bool
	scopeFile   string
	auditLog    string
}

func (f *serveFlags) register(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&f.allowActive, "allow-active", false, "Enable start_authorized_scan/stop_scan (disabled by default; requires --scope)")
	cmd.Flags().StringVarP(&f.scopeFile, "scope", "s", "", "Explicit scope file (mandatory with --allow-active; strict, no implicit scope, no confirmation prompt)")
	cmd.Flags().StringVar(&f.auditLog, "audit-log", "", "JSONL audit log of active calls (default <workspace>/.scanforge-audit.jsonl)")
}

// operatorSecrets gathers the operator's own credentials (auth store, AI key)
// so they can be masked from any API/MCP output.
func operatorSecrets(cfg *config.Config) []string {
	var out []string
	if cfg != nil && cfg.AI.APIKey != "" {
		out = append(out, cfg.AI.APIKey)
	}
	if a, err := auth.Load(); err == nil {
		for _, kv := range a.Providers {
			for _, v := range kv {
				out = append(out, v)
			}
		}
	}
	return out
}

type serveEnv struct {
	idx *runindex.Index
	ctl *active.Controller
}

func (f *serveFlags) build(application *app.App, actor string) (*serveEnv, error) {
	cfg, err := config.Load(config.ResolvePath(application.ConfigPath))
	if err != nil {
		return nil, err
	}
	workspace := config.WorkspaceDir(cfg)
	audit := f.auditLog
	if audit == "" {
		audit = filepath.Join(workspace, ".scanforge-audit.jsonl")
	}
	ctl, err := active.New(active.Config{
		Allow:      f.allowActive,
		ScopeFile:  f.scopeFile,
		AuditPath:  audit,
		LogDir:     filepath.Join(workspace, ".scanforge-active"),
		ConfigPath: application.ConfigPath,
		Actor:      actor,
	}, active.ExecLauncher{}, application.Plan)
	if err != nil {
		return nil, err
	}
	return &serveEnv{idx: runindex.New(workspace, operatorSecrets(cfg)...), ctl: ctl}, nil
}

// NewMCPCommand serves the MCP tools over stdio.
func NewMCPCommand(application *app.App) *cobra.Command {
	var f serveFlags
	cmd := &cobra.Command{
		Use:     "mcp",
		GroupID: groupReports,
		Short:   "Serve ScanForge to AI agents over MCP (stdio)",
		Long: `Starts a Model Context Protocol server on stdin/stdout exposing the run
store (list_runs, get_run, get_assets, get_findings, get_evidence) and plan_scan.
start_authorized_scan and stop_scan stay disabled unless --allow-active is given
together with an explicit --scope file; every active call is audit-logged.`,
		Example: `  scanforge mcp
  scanforge mcp --allow-active --scope scope.txt`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := f.build(application, "mcp")
			if err != nil {
				return err
			}
			srv := &mcp.Server{Index: env.idx, Active: env.ctl, Version: version.Version}
			return srv.Serve(cmd.Context(), cmd.InOrStdin(), cmd.OutOrStdout())
		},
	}
	f.register(cmd)
	return cmd
}

// NewAPICommand serves the local HTTP JSON API.
func NewAPICommand(application *app.App) *cobra.Command {
	var f serveFlags
	var listen, tokenFile string
	var unsafeBind bool
	cmd := &cobra.Command{
		Use:     "api",
		GroupID: groupReports,
		Short:   "Serve the run store over a local HTTP JSON API",
		Long: `Serves runs, assets, findings and evidence read-only on 127.0.0.1.
POST/DELETE endpoints (plan, scans) require a bearer token generated at startup.
Active scanning follows the same rules as 'scanforge mcp'.`,
		Example: `  scanforge api
  scanforge api --listen 127.0.0.1:9000 --token-file /tmp/sf.token`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := api.CheckListenAddr(listen, unsafeBind); err != nil {
				return err
			}
			env, err := f.build(application, "api")
			if err != nil {
				return err
			}
			token := api.NewToken()
			if tokenFile != "" {
				if err := os.WriteFile(tokenFile, []byte(token+"\n"), 0o600); err != nil {
					return fmt.Errorf("write token file: %w", err)
				}
			}
			srv := api.New(env.idx, env.ctl, token)
			if unsafeBind {
				srv.AllowRemoteHosts()
			}
			httpSrv := &http.Server{Addr: listen, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
			errOut := cmd.ErrOrStderr()
			_, _ = fmt.Fprintf(errOut, "scanforge api listening on http://%s\n", listen)
			if tokenFile != "" {
				_, _ = fmt.Fprintf(errOut, "bearer token written to %s\n", tokenFile)
			} else {
				_, _ = fmt.Fprintf(errOut, "bearer token (non-read endpoints): %s\n", token)
			}
			if env.ctl.Allowed() {
				_, _ = fmt.Fprintln(errOut, "ACTIVE MODE ENABLED: scans can be started inside the explicit scope file")
			}
			go func() {
				<-cmd.Context().Done()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = httpSrv.Shutdown(ctx)
			}()
			if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				return err
			}
			return nil
		},
	}
	f.register(cmd)
	cmd.Flags().StringVar(&listen, "listen", "127.0.0.1:8787", "Listen address (loopback only unless --unsafe-bind)")
	cmd.Flags().StringVar(&tokenFile, "token-file", "", "Write the bearer token to this file (0600) instead of stderr")
	cmd.Flags().BoolVar(&unsafeBind, "unsafe-bind", false, "Allow binding a non-loopback address (not recommended)")
	return cmd
}
