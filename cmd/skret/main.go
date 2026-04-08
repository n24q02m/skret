package main

import (
	"fmt"
	"os"

	"github.com/n24q02m/skret/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
