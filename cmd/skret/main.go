package main

import (
	"os"

	"github.com/n24q02m/skret/internal/cli"
	"github.com/n24q02m/skret/pkg/skret"
)

func main() {
	format, err := cli.Execute()
	if err != nil {
		cli.RenderError(os.Stderr, err, format)
		os.Exit(skret.ExitCode(err))
	}
}
