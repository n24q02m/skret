package syncer

import (
	"encoding/json"
	"testing"

	"github.com/n24q02m/skret/internal/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFingerprint_SaltedDeterministic(t *testing.T) {
	salt := []byte("0123456789abcdef")
	a := Fingerprint(salt, "s3cr3t")
	b := Fingerprint(salt, "s3cr3t")
	assert.Equal(t, a, b)                                                     // deterministic within deployment
	assert.Len(t, a, 8)                                                       // 8 hex chars
	assert.NotEqual(t, a, Fingerprint([]byte("different-salt-16"), "s3cr3t")) // salt changes fp
}

func TestBuildManifest_NoValuesLeak(t *testing.T) {
	salt := []byte("0123456789abcdef")
	secrets := []*provider.Secret{{Key: "/a/prod/DB", Value: "$ecret=val"}}
	states := map[string]*SyncState{
		"github:o/r":            {Hashes: map[string]string{"/a/prod/DB": hashSecret("$ecret=val")}}, // in-sync
		"cloudflare:worker/api": {Hashes: map[string]string{}},                                       // never synced -> missing
	}
	m := BuildManifest("/a/prod", "prod", salt, secrets, states)
	raw, _ := json.Marshal(m)
	assert.NotContains(t, string(raw), "$ecret=val") // value never serialized
	require.Len(t, m.Keys, 1)
	assert.Equal(t, "DB", m.Keys[0].Name)
	assert.Equal(t, "in-sync", m.Keys[0].Targets["github:o/r"].Status)
	assert.Equal(t, "missing", m.Keys[0].Targets["cloudflare:worker/api"].Status)
}
