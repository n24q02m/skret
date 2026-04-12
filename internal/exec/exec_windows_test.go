//go:build windows

package exec

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRun(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		err := Run("cmd.exe", []string{"cmd.exe", "/c", "exit", "0"}, os.Environ())
		assert.NoError(t, err)
	})

	t.Run("failure", func(t *testing.T) {
		err := Run("cmd.exe", []string{"cmd.exe", "/c", "exit", "1"}, os.Environ())
		assert.Error(t, err)
	})

	t.Run("env_passing", func(t *testing.T) {
		env := []string{"TEST_VAR=true"}
		err := Run("cmd.exe", []string{"cmd.exe", "/c", "if \"%TEST_VAR%\"==\"true\" (exit 0) else (exit 1)"}, env)
		assert.NoError(t, err)
	})
}
