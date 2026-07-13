package cli

import (
	"bytes"
	"testing"

	"github.com/n24q02m/skret/internal/config"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestWarnIfPathMangled(t *testing.T) {
	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetErr(&buf)

	warnIfPathMangled(cmd, &config.ResolvedConfig{Path: "/myapp/dev", PathMangled: true})
	assert.Contains(t, buf.String(), "warning: --path looked shell-mangled")
	assert.Contains(t, buf.String(), `"/myapp/dev"`)

	buf.Reset()
	warnIfPathMangled(cmd, &config.ResolvedConfig{Path: "/myapp/dev", PathMangled: false})
	assert.Empty(t, buf.String())

	buf.Reset()
	warnIfPathMangled(cmd, nil)
	assert.Empty(t, buf.String())
}
