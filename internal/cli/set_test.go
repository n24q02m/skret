package cli

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetOptions_GetValue_AllPaths(t *testing.T) {
	t.Run("value from args", func(t *testing.T) {
		o := &setOptions{}
		val, err := o.getValue([]string{"KEY", "myvalue"})
		require.NoError(t, err)
		assert.Equal(t, "myvalue", val)
	})

	t.Run("no value no flags", func(t *testing.T) {
		o := &setOptions{}
		_, err := o.getValue([]string{"KEY"})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "value required")
	})

	t.Run("from file", func(t *testing.T) {
		tmpFile := t.TempDir() + "/val.txt"
		require.NoError(t, os.WriteFile(tmpFile, []byte("file_val\n"), 0o644))
		o := &setOptions{fromFile: tmpFile}
		val, err := o.getValue([]string{"KEY"})
		require.NoError(t, err)
		assert.Equal(t, "file_val", val) // trailing newline trimmed
	})

	t.Run("from file not found", func(t *testing.T) {
		o := &setOptions{fromFile: "/nonexistent/file.txt"}
		_, err := o.getValue([]string{"KEY"})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "read file")
	})

	t.Run("from stdin empty", func(t *testing.T) {
		// Create a pipe with empty input
		r, w, _ := os.Pipe()
		w.Close()
		oldStdin := os.Stdin
		os.Stdin = r
		defer func() { os.Stdin = oldStdin }()

		o := &setOptions{fromStdin: true}
		val, err := o.getValue([]string{"KEY"})
		require.NoError(t, err)
		assert.Equal(t, "", val)
	})
}

func TestSetOptions_GetMeta(t *testing.T) {
	t.Run("no tags", func(t *testing.T) {
		o := &setOptions{description: "desc"}
		meta := o.getMeta()
		assert.Equal(t, "desc", meta.Description)
		assert.Nil(t, meta.Tags)
	})

	t.Run("with tags", func(t *testing.T) {
		o := &setOptions{tags: []string{"env=prod", "team=infra"}}
		meta := o.getMeta()
		assert.Equal(t, "prod", meta.Tags["env"])
		assert.Equal(t, "infra", meta.Tags["team"])
	})

	t.Run("malformed tag", func(t *testing.T) {
		o := &setOptions{tags: []string{"noequals"}}
		meta := o.getMeta()
		// Malformed tag with no = sign should be silently ignored
		assert.Empty(t, meta.Tags)
	})
}

func TestNewSetCmd(t *testing.T) {
	opts := &GlobalOpts{}
	cmd := newSetCmd(opts)

	assert.Equal(t, "set <KEY> [VALUE]", cmd.Use)
	assert.True(t, cmd.HasFlags())

	// Check if flags are defined
	assert.NotNil(t, cmd.Flags().Lookup("from-stdin"))
	assert.NotNil(t, cmd.Flags().Lookup("from-file"))
	assert.NotNil(t, cmd.Flags().Lookup("description"))
	assert.NotNil(t, cmd.Flags().Lookup("tag"))
}
