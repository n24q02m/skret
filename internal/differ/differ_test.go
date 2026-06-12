package differ

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeSource is an in-memory Source for engine tests.
type fakeSource struct {
	label   string
	secrets map[string]string
	canRead bool
	readErr error
}

func (f fakeSource) Label() string { return f.label }
func (f fakeSource) Read(_ context.Context) (Snapshot, error) {
	if f.readErr != nil {
		return Snapshot{}, f.readErr
	}
	return Snapshot{Secrets: f.secrets, CanReadValues: f.canRead}, nil
}

func TestDiff_Categories(t *testing.T) {
	a := fakeSource{label: "env:dev", canRead: true, secrets: map[string]string{
		"SHARED_SAME": "x", "SHARED_DIFF": "1", "ONLY_A": "a",
	}}
	b := fakeSource{label: "env:prod", canRead: true, secrets: map[string]string{
		"SHARED_SAME": "x", "SHARED_DIFF": "2", "ONLY_B": "b",
	}}

	res, err := Diff(context.Background(), a, b, Opts{})
	require.NoError(t, err)

	assert.Equal(t, []string{"ONLY_A"}, res.OnlyA)
	assert.Equal(t, []string{"ONLY_B"}, res.OnlyB)
	assert.Equal(t, []string{"SHARED_DIFF"}, res.Changed)
	assert.Empty(t, res.Unknown)
	assert.Equal(t, 1, res.SameCount)
	assert.True(t, res.HasDrift())
}

func TestDiff_PresenceOnly_WhenSideCannotReadValues(t *testing.T) {
	a := fakeSource{label: "env:prod", canRead: true, secrets: map[string]string{
		"A": "1", "B": "2",
	}}
	b := fakeSource{label: "github:o/r", canRead: false, secrets: map[string]string{
		"A": "", "C": "",
	}}

	res, err := Diff(context.Background(), a, b, Opts{})
	require.NoError(t, err)

	assert.Equal(t, []string{"B"}, res.OnlyA)
	assert.Equal(t, []string{"C"}, res.OnlyB)
	assert.Empty(t, res.Changed)
	assert.Equal(t, []string{"A"}, res.Unknown)
	assert.Equal(t, 0, res.SameCount)
}

func TestDiff_Hashes_OptIn(t *testing.T) {
	a := fakeSource{label: "env:dev", canRead: true, secrets: map[string]string{"K": "1"}}
	b := fakeSource{label: "env:prod", canRead: true, secrets: map[string]string{"K": "2"}}

	res, err := Diff(context.Background(), a, b, Opts{Hashes: true})
	require.NoError(t, err)

	require.Contains(t, res.Hashes, "K")
	assert.Len(t, res.Hashes["K"][0], 8)
	assert.Len(t, res.Hashes["K"][1], 8)
	assert.NotEqual(t, res.Hashes["K"][0], res.Hashes["K"][1])
}

func TestDiff_ReadError_Wrapped(t *testing.T) {
	a := fakeSource{label: "env:dev", canRead: true, secrets: map[string]string{}}
	b := fakeSource{label: "env:prod", readErr: assert.AnError}

	_, err := Diff(context.Background(), a, b, Opts{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "diff env:dev vs env:prod")
}

func TestDiff_ReadErrorB_Wrapped(t *testing.T) {
	a := fakeSource{label: "env:dev", canRead: true, secrets: map[string]string{}}
	b := fakeSource{label: "env:prod", readErr: assert.AnError}

	_, err := Diff(context.Background(), a, b, Opts{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "diff env:dev vs env:prod")
}

func TestDiff_ReadErrorA_Wrapped(t *testing.T) {
	a := fakeSource{label: "env:dev", readErr: assert.AnError}
	b := fakeSource{label: "env:prod", canRead: true, secrets: map[string]string{}}

	_, err := Diff(context.Background(), a, b, Opts{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "diff env:dev vs env:prod")
}

func TestDiff_Unknown_WithHashes(t *testing.T) {
	a := fakeSource{label: "env:prod", canRead: true, secrets: map[string]string{"A": "val"}}
	b := fakeSource{label: "github:o/r", canRead: false, secrets: map[string]string{"A": ""}}

	res, err := Diff(context.Background(), a, b, Opts{Hashes: true})
	require.NoError(t, err)

	assert.Equal(t, []string{"A"}, res.Unknown)
	require.Contains(t, res.Hashes, "A")
	assert.NotEqual(t, "?", res.Hashes["A"][0]) // readable side has a real hash
	assert.Equal(t, "?", res.Hashes["A"][1])    // unreadable side returns "?"
}
