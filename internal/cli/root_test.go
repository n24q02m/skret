package cli

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Bug F: the tagline must not advertise providers that are not registered.
func TestRootHelpDoesNotOverpromiseProviders(t *testing.T) {
	long := NewRootCmd().Long
	for _, banned := range []string{"GCP", "Azure", "OCI", "Cloudflare"} {
		if strings.Contains(long, banned) {
			t.Fatalf("root Long advertises unimplemented provider %q: %q", banned, long)
		}
	}
}

func TestNewRootCmd(t *testing.T) {
	cmd := NewRootCmd()

	assert.NotNil(t, cmd)
	assert.Equal(t, "skret", cmd.Use)
	assert.Contains(t, cmd.Short, "secret manager")

	// Verify persistent flags
	flags := cmd.PersistentFlags()
	assert.NotNil(t, flags.Lookup("env"))
	assert.NotNil(t, flags.Lookup("provider"))
	assert.NotNil(t, flags.Lookup("path"))
	assert.NotNil(t, flags.Lookup("region"))
	assert.NotNil(t, flags.Lookup("profile"))
	assert.NotNil(t, flags.Lookup("file"))
	assert.NotNil(t, flags.Lookup("log-level"))

	// Verify subcommands
	expectedSubcommands := []string{
		"init", "get", "list", "env", "set", "delete",
		"history", "rollback", "run", "import", "sync", "auth",
	}

	for _, name := range expectedSubcommands {
		found := false
		for _, sub := range cmd.Commands() {
			if sub.Name() == name {
				found = true
				break
			}
		}
		assert.True(t, found, "subcommand %s should be registered", name)
	}
}
