package scanner

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRenderJSONEmpty(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, RenderJSON(&buf, nil))
	require.Equal(t, "[]\n", buf.String())
}

func TestRenderTableHeader(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, RenderTable(&buf, nil))
	require.True(t, strings.HasPrefix(buf.String(), "KEY"))
}

func TestRenderTableRows(t *testing.T) {
	var buf bytes.Buffer
	findings := []Finding{{Key: "API_KEY", File: "env.txt", Line: 3}}
	require.NoError(t, RenderTable(&buf, findings))
	out := buf.String()
	require.Contains(t, out, "API_KEY")
	require.Contains(t, out, "env.txt")
	require.Contains(t, out, "3")
}

func TestRenderJSONRows(t *testing.T) {
	var buf bytes.Buffer
	findings := []Finding{{Key: "API_KEY", File: "env.txt", Line: 3}}
	require.NoError(t, RenderJSON(&buf, findings))
	out := buf.String()
	require.Contains(t, out, `"key": "API_KEY"`)
	require.Contains(t, out, `"file": "env.txt"`)
	require.Contains(t, out, `"line": 3`)
}

// TestValueSafetyInvariant is the core guarantee: a managed secret value must
// never surface in any Finding field or rendered output (table or JSON).
func TestValueSafetyInvariant(t *testing.T) {
	const secret = "sup3r-s3cret-value"

	dir := t.TempDir()
	f := writeFile(t, dir, "leak.env", "API_KEY="+secret+"\n")

	findings, err := Scan(
		[]Target{{Key: "API_KEY", Value: secret}},
		[]string{f},
		Opts{},
	)
	require.NoError(t, err)
	require.Len(t, findings, 1)

	// No Finding field equals or contains the secret value.
	for _, fnd := range findings {
		require.NotContains(t, fnd.Key, secret)
		require.NotContains(t, fnd.File, secret)
	}

	var tbl, js bytes.Buffer
	require.NoError(t, RenderTable(&tbl, findings))
	require.NoError(t, RenderJSON(&js, findings))

	require.NotContains(t, tbl.String(), secret, "table output leaked the secret value")
	require.NotContains(t, js.String(), secret, "JSON output leaked the secret value")
}
