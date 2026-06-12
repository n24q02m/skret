package differ

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sampleResult() Result {
	return Result{
		A: "env:dev", B: "env:prod",
		OnlyA:     []string{"ONLY_A"},
		OnlyB:     []string{"ONLY_B"},
		Changed:   []string{"DB_URL"},
		SameCount: 2,
	}
}

func TestRenderTable_Sections(t *testing.T) {
	out := RenderTable(sampleResult(), TableOpts{})
	assert.Contains(t, out, "diff env:dev vs env:prod")
	assert.Contains(t, out, "+ only in env:dev")
	assert.Contains(t, out, "ONLY_A")
	assert.Contains(t, out, "- only in env:prod")
	assert.Contains(t, out, "ONLY_B")
	assert.Contains(t, out, "~ differs")
	assert.Contains(t, out, "DB_URL")
	assert.Contains(t, out, "2 same")
}

func TestRenderTable_ShowHash(t *testing.T) {
	r := sampleResult()
	r.Hashes = map[string][2]string{"DB_URL": {"aaaaaaaa", "bbbbbbbb"}}
	out := RenderTable(r, TableOpts{ShowHash: true})
	assert.Contains(t, out, "aaaaaaaa")
	assert.Contains(t, out, "bbbbbbbb")
	assert.Contains(t, out, "→")
}

func TestRenderTable_UnknownSection(t *testing.T) {
	r := Result{A: "env:prod", B: "github:o/r", Unknown: []string{"DB_URL"}}
	out := RenderTable(r, TableOpts{})
	assert.Contains(t, out, "cannot compare values")
	assert.Contains(t, out, "DB_URL")
}

func TestRenderJSON_KeysOnly(t *testing.T) {
	out := RenderJSON(sampleResult())
	var parsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &parsed))
	assert.Equal(t, "env:dev", parsed["a"])
	assert.Equal(t, []any{"DB_URL"}, parsed["changed"])
}

func TestRenderTable_NoDrift(t *testing.T) {
	out := RenderTable(Result{A: "env:dev", B: "env:prod", SameCount: 3}, TableOpts{})
	assert.Contains(t, out, "no drift")
	assert.Contains(t, out, "3 same")
}

// Security invariant: no plaintext value ever reaches any render path.
func TestRender_NeverLeaksValues(t *testing.T) {
	const sentinel = "S3CRET_VALUE_SENTINEL"
	a := fakeSource{label: "env:dev", canRead: true, secrets: map[string]string{"K": sentinel}}
	b := fakeSource{label: "env:prod", canRead: true, secrets: map[string]string{"K": sentinel + "_DIFFERENT"}}

	res, err := Diff(t.Context(), a, b, Opts{Hashes: true})
	require.NoError(t, err)

	table := RenderTable(res, TableOpts{ShowHash: true})
	js := RenderJSON(res)
	assert.False(t, strings.Contains(table, sentinel), "table leaked value")
	assert.False(t, strings.Contains(js, sentinel), "json leaked value")
}
