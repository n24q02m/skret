package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsNonInteractive(t *testing.T) {
	t.Run("SKRET_NON_INTERACTIVE=1", func(t *testing.T) {
		t.Setenv("SKRET_NON_INTERACTIVE", "1")
		assert.True(t, isNonInteractive())
	})

	t.Run("SKRET_NON_INTERACTIVE=0", func(t *testing.T) {
		t.Setenv("SKRET_NON_INTERACTIVE", "0")
		// isNonInteractive should fallback to checking IsInteractiveStdin()
		assert.Equal(t, !IsInteractiveStdin(), isNonInteractive())
	})

	t.Run("SKRET_NON_INTERACTIVE unset", func(t *testing.T) {
		t.Setenv("SKRET_NON_INTERACTIVE", "")
		assert.Equal(t, !IsInteractiveStdin(), isNonInteractive())
	})
}
