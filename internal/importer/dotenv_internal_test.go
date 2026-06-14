package importer

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDotenvImport_Decoding verifies the importer decodes via the shared dotenv
// codec: quoted values are unescaped, single quotes are literal, comments and
// blanks are skipped, and an "export " prefix is stripped. Value-level codec
// round-trip is covered exhaustively in internal/dotenv.
func TestDotenvImport_Decoding(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, ".env")
	content := "" +
		"# a comment\n" +
		"\n" +
		"PLAIN=simple\n" +
		"export EXPORTED=val\n" +
		"QUOTED=\"a\\\"b\\nc\"\n" + // double-quoted with escapes: a"b<newline>c
		"LITERAL='a\\nb'\n" + // single-quoted literal: a\nb (backslash-n)
		"DOLLAR=\"p$word\"\n" +
		"BARE_TRAILING=secret \n" // trailing space preserved
	require.NoError(t, os.WriteFile(file, []byte(content), 0o600))

	got, err := NewDotenv(file).Import(context.Background())
	require.NoError(t, err)

	m := make(map[string]string, len(got))
	for _, s := range got {
		m[s.Key] = s.Value
	}

	assert.Equal(t, "simple", m["PLAIN"])
	assert.Equal(t, "val", m["EXPORTED"])
	assert.Equal(t, "a\"b\nc", m["QUOTED"])
	assert.Equal(t, `a\nb`, m["LITERAL"])
	assert.Equal(t, "p$word", m["DOLLAR"])
	assert.Equal(t, "secret ", m["BARE_TRAILING"])
	assert.NotContains(t, m, "")
}
