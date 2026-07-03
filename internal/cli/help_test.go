package cli_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/n24q02m/skret/internal/cli"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

// knownIncomplete lists leaf commands whose Long/Example are filled in a LATER
// task. It must be empty by end of Task 2. Use the full "skret <path>" name.
var knownIncomplete = map[string]bool{}

// leafCommands returns every runnable (non-parent) command in the tree.
func leafCommands(root *cobra.Command) []*cobra.Command {
	var out []*cobra.Command
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		if c.Runnable() && !c.HasSubCommands() {
			out = append(out, c)
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(root)
	return out
}

func TestHelp_EveryLeafCommandHasLongAndExample(t *testing.T) {
	for _, c := range leafCommands(cli.NewRootCmd()) {
		name := c.CommandPath()
		if name == "skret help" || strings.HasPrefix(name, "skret completion") {
			continue // cobra built-ins
		}
		t.Run(name, func(t *testing.T) {
			if knownIncomplete[name] {
				t.Skipf("%s: Long/Example filled in Task 2", name)
			}
			assert.NotEmpty(t, c.Long, "%s must have a Long description", name)
			assert.NotEmpty(t, c.Example, "%s must have an Example", name)
		})
	}
}

// badSecretSubstrings are fixed real-world credential prefixes that no
// placeholder in this codebase legitimately needs — any match is a real leak.
var badSecretSubstrings = []string{
	"AKIA",               // real AWS access key ID prefix
	"sk-live",            // real Stripe/OpenAI-style live secret key prefix
	"sk-proj",            // real OpenAI project-scoped secret key prefix
	"-----BEGIN RSA",     // real PEM header (placeholder is "-----BEGIN KEY-----")
	"-----BEGIN OPENSSH", // real PEM header
	"-----BEGIN EC",      // real PEM header
	"-----BEGIN DSA",     // real PEM header
	"-----BEGIN PRIVATE", // real PEM header
}

// badSecretPatterns catch the "short fixed prefix + long random token" shape
// of real credentials, without false-flagging the short xxx-style
// placeholders used in the examples (ghp_xxx, dp.pt.xxx).
var badSecretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`ghp_[A-Za-z0-9]{20,}`),     // real GitHub PAT shape
	regexp.MustCompile(`dp\.pt\.[A-Za-z0-9]{20,}`), // real Doppler token shape
}

// parentCommands returns every command in the tree that has subcommands
// (i.e. is not runnable as a leaf), excluding the root "skret" command itself.
func parentCommands(root *cobra.Command) []*cobra.Command {
	var out []*cobra.Command
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		if c.HasSubCommands() && c != root {
			out = append(out, c)
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(root)
	return out
}

func TestHelp_ParentCommandsHaveLong(t *testing.T) {
	for _, c := range parentCommands(cli.NewRootCmd()) {
		name := c.CommandPath()
		t.Run(name, func(t *testing.T) {
			assert.NotEmpty(t, c.Short, "%s must have a Short description", name)
			assert.NotEmpty(t, c.Long, "%s must have a Long description", name)
		})
	}
}

func TestHelp_ExamplesUsePlaceholdersNotSecrets(t *testing.T) {
	// Examples must not contain anything shaped like a real credential.
	for _, c := range leafCommands(cli.NewRootCmd()) {
		text := c.Long + "\n" + c.Example
		for _, b := range badSecretSubstrings {
			assert.NotContains(t, text, b, "%s help must use placeholders, not a real-looking secret (%q)", c.CommandPath(), b)
		}
		for _, re := range badSecretPatterns {
			assert.False(t, re.MatchString(text), "%s help must use placeholders, not a real-looking secret (matches %s)", c.CommandPath(), re.String())
		}
	}
}
