package cli_test

import (
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
