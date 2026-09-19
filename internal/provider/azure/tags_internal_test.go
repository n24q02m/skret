package azure

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/stretchr/testify/assert"
)

func TestTagsEqual(t *testing.T) {
	p := new("a")
	assert.True(t, tagsEqual(nil, nil))
	assert.True(t, tagsEqual(map[string]*string{"k": p}, map[string]*string{"k": new("a")}))
	assert.False(t, tagsEqual(map[string]*string{"k": p}, nil))
	assert.False(t, tagsEqual(map[string]*string{"k": p}, map[string]*string{"k": new("b")}))
	assert.False(t, tagsEqual(map[string]*string{"k": p}, map[string]*string{"other": p}))
	assert.False(t, tagsEqual(
		map[string]*string{"k": p, "k2": p},
		map[string]*string{"k": p},
	))
	// nil vs non-nil value for the same key.
	assert.False(t, tagsEqual(map[string]*string{"k": nil}, map[string]*string{"k": p}))
	assert.False(t, tagsEqual(map[string]*string{"k": p}, map[string]*string{"k": nil}))
	assert.True(t, tagsEqual(map[string]*string{"k": nil}, map[string]*string{"k": nil}))
}

func TestSecretFromResponseIgnoresNilTagValues(t *testing.T) {
	s := azsecrets.Secret{
		Value: new("v"),
		ID:    new(azsecrets.ID("https://test-vault.vault.azure.net/secrets/K/" + padHex(3))),
		Tags:  map[string]*string{"k": nil},
	}
	secret := secretFromResponse("K", s)
	assert.Equal(t, int64(3), secret.Version)
	assert.Empty(t, secret.Meta.Tags, "nil tag values are skipped")
}

// padHex renders a counter in the 15-hex-char fold window, matching the
// shape of real Key Vault version IDs.
func padHex(n int) string {
	const digits = "0123456789abcdef"
	out := []byte("000000000000000")
	for i := len(out) - 1; n > 0 && i >= 0; i, n = i-1, n/16 {
		out[i] = digits[n%16]
	}
	return string(out)
}
