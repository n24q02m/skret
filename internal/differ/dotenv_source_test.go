package differ

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDotenvSource_ReadsAndNormalizes(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, ".env")
	require.NoError(t, os.WriteFile(p, []byte("DB_URL=postgres://x\nAPI_KEY=secret\n"), 0o600))

	src := NewDotenvSource(p)
	snap, err := src.Read(context.Background())
	require.NoError(t, err)

	assert.True(t, snap.CanReadValues)
	assert.Equal(t, "postgres://x", snap.Secrets["DB_URL"])
	assert.Equal(t, "secret", snap.Secrets["API_KEY"])
	assert.Equal(t, "file:"+p, src.Label())
}

func TestDotenvSource_MissingFile(t *testing.T) {
	src := NewDotenvSource(filepath.Join(t.TempDir(), "nope.env"))
	_, err := src.Read(context.Background())
	require.Error(t, err)
}
