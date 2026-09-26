package keystore

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSealWithMetaRoundTrip(t *testing.T) {
	secrets := map[string]string{"API_KEY": "v1", "DB_PASS": "v2"}
	meta := map[string]string{"API_KEY": "2026-10-19T00:00:00Z"}

	raw, err := SealWithMeta(secrets, meta, "test-material")
	require.NoError(t, err)
	assert.True(t, Detect(raw), "output must remain a detected age envelope")

	gotSecrets, gotMeta, err := OpenWithMeta(raw, "test-material")
	require.NoError(t, err)
	assert.Equal(t, secrets, gotSecrets)
	assert.Equal(t, meta, gotMeta)
}

func TestSealNilMetaMatchesSeal(t *testing.T) {
	secrets := map[string]string{"K": "v"}

	withNil, err := SealWithMeta(secrets, nil, "m")
	require.NoError(t, err)
	direct, err := Seal(secrets, "m")
	require.NoError(t, err)

	// Both decrypt identically; the payload omits an empty meta section.
	got, gotMeta, err := OpenWithMeta(withNil, "m")
	require.NoError(t, err)
	assert.Equal(t, secrets, got)
	assert.Nil(t, gotMeta)

	got2, err := Open(direct, "m")
	require.NoError(t, err)
	assert.Equal(t, secrets, got2)
}

func TestOpenIgnoresMetaSection(t *testing.T) {
	secrets := map[string]string{"K": "v"}
	raw, err := SealWithMeta(secrets, map[string]string{"K": "2026-10-19T00:00:00Z"}, "m")
	require.NoError(t, err)

	// The Open entry point keeps working on meta-carrying envelopes.
	got, err := Open(raw, "m")
	require.NoError(t, err)
	assert.Equal(t, secrets, got)
}

func TestLegacyMetaRoundTrip(t *testing.T) {
	secrets := map[string]string{"API_KEY": "v1"}
	meta := map[string]string{"API_KEY": "2026-10-19T00:00:00Z"}
	raw, err := SealLegacyWithMeta(secrets, meta, "m", nil)
	require.NoError(t, err)
	assert.True(t, DetectLegacy(raw), "legacy seal must stay legacy-format detectable")
	assert.False(t, Detect(raw), "legacy envelope must not be detected as age")

	gotSecrets, gotMeta, err := OpenLegacyWithMeta(raw, "m")
	require.NoError(t, err)
	assert.Equal(t, secrets, gotSecrets)
	assert.Equal(t, meta, gotMeta)

	// The plain legacy Open entry point keeps working.
	got, err := OpenLegacy(raw, "m")
	require.NoError(t, err)
	assert.Equal(t, secrets, got)
}
