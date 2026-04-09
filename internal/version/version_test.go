package version_test

import (
	"testing"

	"github.com/n24q02m/skret/internal/version"
	"github.com/stretchr/testify/assert"
)

func TestString_Default(t *testing.T) {
	s := version.String()
	assert.Contains(t, s, "skret")
	assert.Contains(t, s, "0.0.0-dev")
}
