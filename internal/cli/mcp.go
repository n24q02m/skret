package cli

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/n24q02m/skret/internal/mcp"
	"github.com/n24q02m/skret/internal/version"
	"github.com/n24q02m/skret/pkg/skret"
	"github.com/spf13/cobra"
)

type mcpOptions struct {
	global    *GlobalOpts
	workDir   string
	transport string
	addr      string
	token     string
}

func newMCPCmd(global *GlobalOpts) *cobra.Command {
	o := &mcpOptions{global: global}

	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "Start the skret MCP (Model Context Protocol) server",
		Long: `Expose a .skret.yaml project to AI agent harnesses (Claude Code, OMP, and
any MCP client) over stdio or Streamable HTTP.

Read tools (skret_list, skret_get, skret_env, skret_status, skret_doctor)
are always available. Write tools (skret_set, skret_delete, skret_rotate)
are disabled unless mcp.allow_write: true is set in .skret.yaml and each
call passes confirm: true.`,
		Example: `  skret mcp
  skret mcp --workdir /path/to/project
  skret mcp --transport http --addr 127.0.0.1:8787`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.run(cmd)
		},
	}

	cmd.Flags().StringVar(&o.workDir, "workdir", "", "directory to discover .skret.yaml from (default: current directory)")
	cmd.Flags().StringVar(&o.transport, "transport", "stdio", "MCP transport: stdio or http")
	cmd.Flags().StringVar(&o.addr, "addr", "127.0.0.1:8787", "HTTP listen address for --transport=http")
	cmd.Flags().StringVar(&o.token, "token", "", "bearer token for --transport=http (overrides SKRET_MCP_TOKEN)")

	return cmd
}

func (o *mcpOptions) run(cmd *cobra.Command) error {
	if o.transport != "stdio" && o.transport != "http" {
		return skret.NewError(
			skret.ExitValidationError,
			fmt.Sprintf("mcp: unknown --transport %q (stdio, http)", o.transport),
			nil,
		)
	}

	bearer := o.token
	if bearer == "" {
		bearer = os.Getenv("SKRET_MCP_TOKEN")
	}
	if o.transport == "http" {
		if err := mcp.ValidateHTTPAddr(o.addr, bearer); err != nil {
			return skret.NewError(skret.ExitValidationError, err.Error(), err)
		}
	}

	server, err := mcp.New(mcp.Options{
		WorkDir:  o.workDir,
		Env:      o.global.Env,
		Provider: o.global.Provider,
		Path:     o.global.Path,
		Version:  version.Version,
	})
	if err != nil {
		return err
	}
	defer server.Close() //nolint:errcheck // best-effort release on the way out

	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if o.transport == "http" {
		if err := server.ServeHTTP(ctx, o.addr, bearer); err != nil {
			return skret.NewError(skret.ExitGenericError, "mcp: serve http", err)
		}
		return nil
	}

	done := make(chan error, 1)
	go func() {
		done <- server.Serve(cmd.InOrStdin(), cmd.OutOrStdout())
	}()

	select {
	case err := <-done:
		if err != nil {
			return skret.NewError(skret.ExitGenericError, "mcp: serve stdio", err)
		}
		return nil
	case <-ctx.Done():
		return nil
	}
}
