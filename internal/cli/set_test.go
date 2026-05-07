package cli

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetOptions_GetValue_Stdin(t *testing.T) {
	r, w, _ := os.Pipe()
	_, err := w.WriteString("stdin_value\n")
	require.NoError(t, err)
	w.Close()

	oldStdin := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = oldStdin }()

	o := &setOptions{fromStdin: true}
	val, err := o.getValue([]string{"KEY"})
	require.NoError(t, err)
	assert.Equal(t, "stdin_value", val)
}

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

	assert.Equal(t, "set", cmd.Name())
	assert.True(t, cmd.HasFlags())

	flags := []struct {
		name      string
		shorthand string
	}{
		{"from-stdin", "s"},
		{"from-file", "f"},
		{"description", "d"},
		{"tag", "t"},
	}

	for _, f := range flags {
		flag := cmd.Flags().Lookup(f.name)
		require.NotNil(t, flag, "flag %s should exist", f.name)
		assert.Equal(t, f.shorthand, flag.Shorthand, "shorthand for %s should be %s", f.name, f.shorthand)
	}
}

func TestSetOptions_Run(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(dir+"/.git", 0o755))

	configPath := dir + "/.skret.yaml"
	secretsPath := dir + "/secrets.yaml"

	require.NoError(t, os.WriteFile(configPath, []byte(`
version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: ./secrets.yaml
`), 0o644))

	require.NoError(t, os.WriteFile(secretsPath, []byte(`
version: "1"
secrets: {}
`), 0o600))

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	t.Run("success", func(t *testing.T) {
		opts := &GlobalOpts{}
		cmd := newSetCmd(opts)
		var buf bytes.Buffer
		cmd.SetOut(&buf)

		o := &setOptions{
			globals: opts,
		}

		err := o.run(cmd, []string{"NEW_KEY", "new_value"})
		require.NoError(t, err)
		assert.Contains(t, buf.String(), "Set NEW_KEY")

		// Verify file content
		data, err := os.ReadFile(secretsPath)
		require.NoError(t, err)
		assert.Contains(t, string(data), "NEW_KEY: new_value")
	})

	t.Run("provider load error", func(t *testing.T) {
		// Use a non-existent config by changing directory
		tmpDir := t.TempDir()
		require.NoError(t, os.Chdir(tmpDir))
		defer os.Chdir(dir)

		opts := &GlobalOpts{}
		o := &setOptions{globals: opts}
		cmd := newSetCmd(opts)

		err := o.run(cmd, []string{"KEY", "VAL"})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "find config")
	})

	t.Run("get value error", func(t *testing.T) {
		opts := &GlobalOpts{}
		o := &setOptions{globals: opts}
		cmd := newSetCmd(opts)

		// missing value and no flags
		err := o.run(cmd, []string{"KEY"})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "value required")
	})
}
