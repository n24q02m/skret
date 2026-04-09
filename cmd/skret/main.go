package main

import (
	"fmt"
	"os"

	"github.com/n24q02m/skret/internal/cli"
	"github.com/n24q02m/skret/pkg/skret"
)

func main() {
	if err := cli.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(skret.ExitCode(err))
	}
}
