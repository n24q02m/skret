package keystore

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSealWithMetaRoundTrip(t *testing.T) {
	secrets := map[string]string{"API_KEY": "v1", "DB_PASS": "v2"}
	meta := map[string]string{"API_KEY": "2026-10-19T00:00:00Z"}

	raw, err := SealWithMeta(secrets, meta, "test-material", nil)
	require.NoError(t, err)
	assert.True(t, Detect(raw), "output must remain a keystore envelope")

	gotSecrets, gotMeta, err := OpenWithMeta(raw, "test-material")
	require.NoError(t, err)
	assert.Equal(t, secrets, gotSecrets)
	assert.Equal(t, meta, gotMeta)
}

func TestSealNilMetaMatchesSeal(t *testing.T) {
	secrets := map[string]string{"K": "v"}

	withNil, err := SealWithMeta(secrets, nil, "m", nil)
	require.NoError(t, err)
	direct, err := Seal(secrets, "m", nil)
	require.NoError(t, err)

	assert.NotContains(t, string(withNil), "meta:", "nil meta must not add a meta section")
	assert.NotContains(t, string(direct), "meta:")
	// Both decrypt identically.
	got, gotMeta, err := OpenWithMeta(withNil, "m")
	require.NoError(t, err)
	assert.Equal(t, secrets, got)
	assert.Nil(t, gotMeta)
}

func TestOpenIgnoresMetaSection(t *testing.T) {
	secrets := map[string]string{"K": "v"}
	raw, err := SealWithMeta(secrets, map[string]string{"K": "2026-10-19T00:00:00Z"}, "m", nil)
	require.NoError(t, err)

	// The legacy Open entry point keeps working on meta-carrying envelopes.
	got, err := Open(raw, "m")
	require.NoError(t, err)
	assert.Equal(t, secrets, got)
}

func TestOpenWithMetaOnLegacyEnvelope(t *testing.T) {
	// An envelope written before metadata existed (no meta key at all).
	raw, err := Seal(map[string]string{"K": "legacy"}, "m", nil)
	require.NoError(t, err)

	got, gotMeta, err := OpenWithMeta(raw, "m")
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"K": "legacy"}, got)
	assert.Nil(t, gotMeta, "legacy envelopes carry no meta")
}
