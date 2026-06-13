package cli

import (
	"context"
	"errors"
	"os"
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

// TestBrowseReveal covers the provider-backed reveal closure: it returns the
// decrypted value for an existing key and an error (no value) for a missing one.
func TestBrowseReveal(t *testing.T) {
	dir := writeLocalTemplateConfig(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck

	_, p, err := loadProvider(&GlobalOpts{})
	require.NoError(t, err)
	defer p.Close()

	reveal := browseReveal(p)

	val, err := reveal(context.Background(), "TOKEN")
	require.NoError(t, err)
	assert.Equal(t, "tok123", val)

	_, err = reveal(context.Background(), "NOPE")
	require.Error(t, err)
}
