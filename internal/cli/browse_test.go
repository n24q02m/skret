package cli

import (
	"errors"
	"testing"

	"github.com/n24q02m/skret/pkg/skret"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBrowseCmd_NonTTY_Errors(t *testing.T) {
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"browse"})
	err := cmd.Execute()
	require.Error(t, err)

	var se *skret.Error
	require.True(t, errors.As(err, &se))
	assert.Equal(t, skret.ExitValidationError, se.Code)
}

func TestBrowseCmd_Registered(t *testing.T) {
	cmd := NewRootCmd()
	found, _, err := cmd.Find([]string{"browse"})
	require.NoError(t, err)
	assert.Equal(t, "browse", found.Name())
}
