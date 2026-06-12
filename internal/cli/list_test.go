package cli

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListCmd_NoValues_UsesNamesOnly(t *testing.T) {
	dir := writeLocalTemplateConfig(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck

	var out bytes.Buffer
	cmd := NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"list"})
	require.NoError(t, cmd.Execute())

	s := out.String()
	assert.Contains(t, s, "DB_URL")
	assert.Contains(t, s, "TOKEN")
	assert.NotContains(t, s, "VERSION") // VERSION column dropped when values not requested
	assert.NotContains(t, s, "tok123")  // secret value must never leak in plain list
}

func TestListCmd_Values_ShowsVersion(t *testing.T) {
	dir := writeLocalTemplateConfig(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck

	var out bytes.Buffer
	cmd := NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"list", "--values"})
	require.NoError(t, cmd.Execute())

	s := out.String()
	assert.Contains(t, s, "DB_URL")
	assert.Contains(t, s, "TOKEN")
	assert.Contains(t, s, "VERSION")
	assert.Contains(t, s, "tok123") // values requested, so value is shown
}

func TestListCmd_NoValues_JSON(t *testing.T) {
	dir := writeLocalTemplateConfig(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck

	var out bytes.Buffer
	cmd := NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"list", "--format", "json"})
	require.NoError(t, cmd.Execute())

	s := out.String()
	assert.Contains(t, s, "\"key\"")
	assert.Contains(t, s, "DB_URL")
	assert.Contains(t, s, "TOKEN")
	assert.NotContains(t, s, "\"version\"")
	assert.NotContains(t, s, "tok123") // secret value must never leak in plain list json
}
