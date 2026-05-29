package local

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/n24q02m/skret/internal/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSave_Internal(t *testing.T) {
	t.Run("MarshalError", func(t *testing.T) {
		old := marshalYAML
		defer func() { marshalYAML = old }()
		marshalYAML = func(v interface{}) ([]byte, error) {
			return nil, errors.New("marshal error")
		}
		p := &Provider{}
		err := p.save()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "marshal")
	})

	t.Run("WriteError", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, ".secrets.yaml")
		require.NoError(t, os.WriteFile(path, []byte("version: \"1\"\nsecrets:\n  K: v"), 0o600))
		p := &Provider{filePath: path}
		require.NoError(t, p.load())

		require.NoError(t, os.RemoveAll(dir))
		require.NoError(t, os.WriteFile(dir, []byte("blocker"), 0o600))
		err := p.save()
		assert.Error(t, err)
	})

	t.Run("RenameError", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, ".secrets.yaml")
		require.NoError(t, os.WriteFile(path, []byte("version: \"1\"\nsecrets:\n  K: v"), 0o600))
		p := &Provider{filePath: path}
		require.NoError(t, p.load())

		require.NoError(t, os.Remove(path))
		require.NoError(t, os.Mkdir(path, 0o700))
		err := p.save()
		assert.Error(t, err)
	})
}

func TestLoad_Internal(t *testing.T) {
	t.Run("MissingFile", func(t *testing.T) {
		p := &Provider{filePath: filepath.Join(t.TempDir(), "none.yaml")}
		err := p.load()
		assert.NoError(t, err)
		assert.NotNil(t, p.data.Secrets)
	})

	t.Run("ReadError", func(t *testing.T) {
		p := &Provider{filePath: t.TempDir()}
		err := p.load()
		assert.Error(t, err)
	})
}

func TestProvider_InternalOps(t *testing.T) {
	p := &Provider{data: localFile{Secrets: map[string]string{"k": "v"}}}
	ctx := context.Background()

	t.Run("GetNotFound", func(t *testing.T) {
		_, err := p.Get(ctx, "none")
		assert.ErrorIs(t, err, provider.ErrNotFound)
	})

	t.Run("DeleteNotFound", func(t *testing.T) {
		err := p.Delete(ctx, "none")
		assert.ErrorIs(t, err, provider.ErrNotFound)
	})
}
