package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	content, err := os.ReadFile(".github/workflows/ci.yml")
	if err != nil {
		panic(err)
	}

	str := string(content)

	// Clean up multiple env blocks if any
	str = strings.Replace(str, "env:\n  FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true\n  GOTOOLCHAIN: local\n\n", "", -1)
	str = strings.Replace(str, "env:\n  FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true\n  CGO_ENABLED: \"0\"\n  GOTOOLCHAIN: local\n\n", "", -1)
	str = strings.Replace(str, "env:\n  FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true\n  CGO_ENABLED: 0\n  GOTOOLCHAIN: local\n\n", "", -1)

	// Ensure exactly one env block right before jobs
	envBlock := "env:\n  FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true\n  GOTOOLCHAIN: local\n\njobs:\n"
	str = strings.Replace(str, "jobs:\n", envBlock, 1)

	err = os.WriteFile(".github/workflows/ci.yml", []byte(str), 0644)
	if err != nil {
		panic(err)
	}
	fmt.Println("Fixed ci.yml")
}
