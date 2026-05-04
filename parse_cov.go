package main

import (
	"fmt"
	"golang.org/x/tools/cover"
)

func main() {
	profiles, err := cover.ParseProfiles("coverage.out")
	if err != nil {
		panic(err)
	}

	for _, p := range profiles {
		if p.FileName == "github.com/n24q02m/skret/internal/auth/prompt.go" {
			for _, b := range p.Blocks {
				if b.Count == 0 {
					fmt.Printf("Uncovered block: line %d to %d\n", b.StartLine, b.EndLine)
				}
			}
		}
	}
}
