//go:build !windows

package exec

import (
	"fmt"
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRun(t *testing.T) {
	if os.Getenv("BE_HELPER") == "1" {
		helper()
		return
	}

	t.Run("success", func(t *testing.T) {
		cmd := exec.Command(os.Args[0], "-test.run=TestRun")
		cmd.Env = append(os.Environ(), "BE_HELPER=1", "HELPER_CMD=true")
		err := cmd.Run()
		assert.NoError(t, err)
	})

	t.Run("failure", func(t *testing.T) {
		cmd := exec.Command(os.Args[0], "-test.run=TestRun")
		cmd.Env = append(os.Environ(), "BE_HELPER=1", "HELPER_CMD=false")
		err := cmd.Run()
		assert.Error(t, err)
	})

	t.Run("env_passing", func(t *testing.T) {
		cmd := exec.Command(os.Args[0], "-test.run=TestRun")
		cmd.Env = append(os.Environ(), "BE_HELPER=1", "HELPER_CMD=check_env", "TEST_VAR=true")
		err := cmd.Run()
		assert.NoError(t, err)
	})
}

func helper() {
	helperCmd := os.Getenv("HELPER_CMD")
	switch helperCmd {
	case "true":
		binary, err := exec.LookPath("true")
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "lookpath failed: %v", err)
			os.Exit(1)
		}
		_ = Run(binary, []string{"true"}, os.Environ())
	case "false":
		binary, err := exec.LookPath("false")
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "lookpath failed: %v", err)
			os.Exit(1)
		}
		_ = Run(binary, []string{"false"}, os.Environ())
	case "check_env":
		if os.Getenv("TEST_VAR") == "true" {
			binary, _ := exec.LookPath("true")
			_ = Run(binary, []string{"true"}, os.Environ())
		} else {
			binary, _ := exec.LookPath("false")
			_ = Run(binary, []string{"false"}, os.Environ())
		}
	}
	os.Exit(2) // Should not be reached if Run succeeds
}
