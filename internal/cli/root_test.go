package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewRootCmd(t *testing.T) {
	cmd := NewRootCmd()
	assert.NotNil(t, cmd)
	assert.Equal(t, "skret", cmd.Use)
	assert.True(t, cmd.SilenceUsage)
	assert.True(t, cmd.SilenceErrors)

	// Check persistent flags
	flags := cmd.PersistentFlags()
	assert.NotNil(t, flags.Lookup("env"))
	assert.NotNil(t, flags.Lookup("provider"))
	assert.NotNil(t, flags.Lookup("path"))
	assert.NotNil(t, flags.Lookup("region"))
	assert.NotNil(t, flags.Lookup("profile"))
	assert.NotNil(t, flags.Lookup("file"))
	assert.NotNil(t, flags.Lookup("log-level"))

	// Check default log-level
	lvl, _ := flags.GetString("log-level")
	assert.Equal(t, "info", lvl)
}

func TestNewRootCmd_Subcommands(t *testing.T) {
	cmd := NewRootCmd()
	expected := []string{
		"init", "get", "list", "env", "set", "delete",
		"history", "rollback", "run", "import", "sync",
	}

	for _, name := range expected {
		sub, _, err := cmd.Find([]string{name})
		assert.NoError(t, err)
		assert.NotNil(t, sub)
		assert.Equal(t, name, sub.Name())
	}
}

func TestExecute_Basic(t *testing.T) {
	// Execute() just calls NewRootCmd().Execute()
	// When no args are passed, it defaults to showing help.
	assert.NotPanics(t, func() {
		err := Execute()
		assert.NoError(t, err)
	})
}

func TestGlobalOpts_Struct(t *testing.T) {
	opts := GlobalOpts{
		Env:      "dev",
		Provider: "aws",
		Path:     "/app",
		Region:   "us-east-1",
		Profile:  "default",
		File:     "secrets.yaml",
		LogLevel: "debug",
	}
	assert.Equal(t, "dev", opts.Env)
	assert.Equal(t, "aws", opts.Provider)
	assert.Equal(t, "/app", opts.Path)
	assert.Equal(t, "us-east-1", opts.Region)
	assert.Equal(t, "default", opts.Profile)
	assert.Equal(t, "secrets.yaml", opts.File)
	assert.Equal(t, "debug", opts.LogLevel)
}
