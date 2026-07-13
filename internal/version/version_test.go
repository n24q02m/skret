package version_test

import (
	"testing"

	"github.com/n24q02m/skret/internal/version"
	"github.com/stretchr/testify/assert"
)

func TestString_Default(t *testing.T) {
	s := version.String()
	assert.NotContains(t, s, "skret", "String() must not embed the program name -- cobra's version template already prepends it (fix M1 double-prefix)")
	assert.Contains(t, s, "0.0.0-dev")
}
