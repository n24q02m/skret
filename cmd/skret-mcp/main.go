// Command skret-mcp is an MCP (Model Context Protocol) server exposing a
// skret project over stdio. Read tools (skret_list, skret_get, skret_env,
// skret_status) are always available; write tools (skret_set, skret_delete,
// skret_rotate) require mcp.allow_write: true in .skret.yaml. Configuration
// resolution is identical to the skret CLI: .skret.yaml discovered from the
// working directory (or --workdir), with the usual --env/--provider/--path
// overrides.
//
// Protocol: newline-delimited JSON-RPC 2.0 on stdin/stdout (MCP stdio
// transport). Diagnostics go to stderr only; stdout carries protocol
// messages exclusively.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/n24q02m/skret/internal/mcp"
	"github.com/n24q02m/skret/internal/version"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, input io.Reader, output, diagnostics io.Writer) int {
	fs := flag.NewFlagSet("skret-mcp", flag.ContinueOnError)
	fs.SetOutput(diagnostics)
	showVersion := fs.Bool("version", false, "print version and exit")
	workDir := fs.String("workdir", "", "directory to discover .skret.yaml from (default: current directory)")
	env := fs.String("env", "", "target environment (overrides default_env)")
	providerOverride := fs.String("provider", "", "override the provider")
	pathOverride := fs.String("path", "", "override the secret path prefix")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(diagnostics, "skret-mcp: invalid arguments")
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(diagnostics, "skret-mcp: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	if *showVersion {
		fmt.Fprintf(output, "skret-mcp %s\n", version.Version)
		return 0
	}

	server, err := mcp.New(mcp.Options{
		WorkDir:  *workDir,
		Env:      *env,
		Provider: *providerOverride,
		Path:     *pathOverride,
		Version:  version.Version,
	})
	if err != nil {
		fmt.Fprintln(diagnostics, err)
		return 2
	}
	defer server.Close() //nolint:errcheck // best-effort release on the way out

	// Ctrl-C / SIGTERM ends the serve loop cleanly instead of killing the
	// process mid-response.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() {
		done <- server.Serve(input, output)
	}()

	select {
	case err := <-done:
		if err != nil {
			fmt.Fprintln(diagnostics, err)
			return 1
		}
		return 0
	case <-ctx.Done():
		return 0
	}
}
