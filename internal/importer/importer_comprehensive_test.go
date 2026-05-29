package importer_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/n24q02m/skret/internal/importer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Dotenv edge cases ---

func TestDotenvImporter_MultiLineEscaped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	// Use literal strings to avoid shell expansion issues during file creation
	content := "MULTI=\"line1\\nline2\\ttab\"\n" +
		"SINGLE_QUOTES='no expansion $VAR'\n" +
		"EMPTY_QUOTED=\"\"\n" +
		"BARE_VALUE=just_text\n" +
		"NO_EQUALS_LINE\n" +
		"=NO_KEY\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	imp := importer.NewDotenv(path)
	secrets, err := imp.Import(context.Background())
	require.NoError(t, err)

	m := make(map[string]string)
	for _, s := range secrets {
		m[s.Key] = s.Value
	}

	assert.Equal(t, "line1\\nline2\\ttab", m["MULTI"])
	assert.Equal(t, "no expansion $VAR", m["SINGLE_QUOTES"])
	assert.Equal(t, "", m["EMPTY_QUOTED"])
	assert.Equal(t, "just_text", m["BARE_VALUE"])
	// "NO_EQUALS_LINE" should be skipped (no = sign)
	_, hasNoEquals := m["NO_EQUALS_LINE"]
	assert.False(t, hasNoEquals)
	// "=NO_KEY" has empty key
	_, hasEmptyKey := m[""]
	assert.True(t, hasEmptyKey)
}

func TestDotenvImporter_WithExportPrefix(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	content := "export KEY1=value1\nexport KEY2=\"quoted value\"\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	imp := importer.NewDotenv(path)
	secrets, err := imp.Import(context.Background())
	require.NoError(t, err)

	m := make(map[string]string)
	for _, s := range secrets {
		m[s.Key] = s.Value
	}
	assert.Equal(t, "value1", m["KEY1"])
	assert.Equal(t, "quoted value", m["KEY2"])
}

func TestDotenvImporter_SpecialChars(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	content := "URL=https://host:5432/db?sslmode=require\nJSON_VALUE={\"key\":\"value\"}\nSPACES=  has leading and trailing\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	imp := importer.NewDotenv(path)
	secrets, err := imp.Import(context.Background())
	require.NoError(t, err)

	m := make(map[string]string)
	for _, s := range secrets {
		m[s.Key] = s.Value
	}
	assert.Equal(t, "https://host:5432/db?sslmode=require", m["URL"])
	assert.Equal(t, "{\"key\":\"value\"}", m["JSON_VALUE"])
}

func TestDotenvImporter_LargeFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	var b strings.Builder
	for i := 0; i < 100; i++ {
		b.WriteString("KEY_" + strings.Repeat("A", 5) + "=value\n")
	}
	require.NoError(t, os.WriteFile(path, []byte(b.String()), 0o644))

	imp := importer.NewDotenv(path)
	secrets, err := imp.Import(context.Background())
	require.NoError(t, err)
	assert.Len(t, secrets, 100)
}
