package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"

	"github.com/n24q02m/skret/internal/secretlaunch"
)

type stdio struct {
	io.Reader
	io.Writer
}

func (s stdio) Close() error {
	if closer, ok := s.Reader.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, input io.Reader, output io.Writer, diagnostics io.Writer) int {
	flags := flag.NewFlagSet("skret-secret-helper", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	manifestPath := flags.String("manifest", "", "signed launch manifest path")
	trustPath := flags.String("trust", "", "trust allowlist path")
	runtimeID := flags.String("runtime", "", "explicit runtime binding")
	serviceID := flags.String("service", "", "explicit service binding")
	if err := flags.Parse(args); err != nil {
		fmt.Fprintln(diagnostics, "secret helper: invalid arguments")
		return 2
	}
	if *manifestPath == "" || *trustPath == "" || *runtimeID == "" || *serviceID == "" || flags.NArg() != 0 {
		fmt.Fprintln(diagnostics, "secret helper: manifest, trust, runtime, and service are required")
		return 2
	}
	signed, err := secretlaunch.ReadRegularFile(*manifestPath, secretlaunch.MaxSignedManifestBytes)
	if err != nil {
		fmt.Fprintln(diagnostics, "secret helper: manifest unavailable")
		return 1
	}
	trustBytes, err := secretlaunch.ReadRegularFile(*trustPath, secretlaunch.MaxTrustDocumentBytes)
	if err != nil {
		fmt.Fprintln(diagnostics, "secret helper: trust unavailable")
		return 1
	}
	policy, err := secretlaunch.LoadTrustDocument(trustBytes)
	secretlaunch.Zeroize(trustBytes)
	if err != nil {
		fmt.Fprintln(diagnostics, err)
		return 1
	}
	starter := secretlaunch.ExecStarter{}
	helper, err := secretlaunch.NewHelper(signed, policy, starter)
	secretlaunch.Zeroize(signed)
	if err != nil {
		fmt.Fprintln(diagnostics, err)
		return 1
	}
	executable, err := os.Executable()
	if err != nil || secretlaunch.VerifyRegularFileDigest(executable, helper.Manifest.Digests.Helper, 256<<20) != nil {
		fmt.Fprintln(diagnostics, "secret helper: executable binding rejected")
		return 1
	}
	if err := helper.Bind(secretlaunch.LaunchBinding{RuntimeID: *runtimeID, Service: *serviceID}); err != nil {
		fmt.Fprintln(diagnostics, err)
		return 1
	}
	signals := make(chan os.Signal, 8)
	signal.Notify(signals)
	defer signal.Stop(signals)
	helper.Signals = signals
	code, err := helper.RunHandshake(context.Background(), stdio{Reader: input, Writer: output})
	if err != nil {
		fmt.Fprintln(diagnostics, err)
		if code == 0 {
			return 1
		}
		return code
	}
	return code
}
