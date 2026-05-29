package logging

import (
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewRedactingHandler(t *testing.T) {
	inner := slog.NewTextHandler(os.Stderr, nil)
	handler := NewRedactingHandler(inner)

	assert.NotNil(t, handler)
	assert.Equal(t, inner, handler.inner)
}
