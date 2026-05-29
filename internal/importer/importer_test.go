package importer_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/n24q02m/skret/internal/importer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDotenvImporter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	content := `# Database
DATABASE_URL="postgres://user:pass@host/db"
API_KEY=secret123
EMPTY=
export PREFIXED="with_export"
# Comment line
MULTI_LINE="line1\nline2"
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	imp := importer.NewDotenv(path)
	assert.Equal(t, "dotenv", imp.Name())

	secrets, err := imp.Import(context.Background())
	require.NoError(t, err)
	assert.Len(t, secrets, 5)

	m := make(map[string]string)
	for _, s := range secrets {
		m[s.Key] = s.Value
	}
	assert.Equal(t, "postgres://user:pass@host/db", m["DATABASE_URL"])
	assert.Equal(t, "secret123", m["API_KEY"])
	assert.Equal(t, "", m["EMPTY"])
	assert.Equal(t, "with_export", m["PREFIXED"])
}

func TestDotenvImporter_FileMissing(t *testing.T) {
	imp := importer.NewDotenv(filepath.Join(t.TempDir(), "nonexistent.env"))
	_, err := imp.Import(context.Background())
	assert.Error(t, err)
}

func TestDotenvImporter_Empty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	require.NoError(t, os.WriteFile(path, []byte("# Only comments\n"), 0o644))

	imp := importer.NewDotenv(path)
	secrets, err := imp.Import(context.Background())
	require.NoError(t, err)
	assert.Empty(t, secrets)
}
