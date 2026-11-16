package keystore

import (
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// scryptStanzaWorkFactor returns the work factor (log2 N) recorded in the
// scrypt recipient stanza of an age file: "-> scrypt <salt> <logN>".
func scryptStanzaWorkFactor(t *testing.T, raw []byte) string {
	t.Helper()
	for _, line := range strings.Split(string(raw), "\n") {
		if fields := strings.Fields(line); len(fields) == 4 && fields[0] == "->" && fields[1] == "scrypt" {
			return fields[3]
		}
	}
	t.Fatal("age file must carry a scrypt recipient stanza")
	return ""
}

// TestScryptWorkFactorFor pins both work factors: shipped binaries keep
// age's default, and test binaries use the low factor age's own suite uses.
func TestScryptWorkFactorFor(t *testing.T) {
	assert.Equal(t, 18, scryptWorkFactorFor(false), "shipped binaries must keep age's default work factor")
	assert.Equal(t, 10, scryptWorkFactorFor(true))
	assert.Equal(t, scryptWorkFactorFor(true), scryptWorkFactor, "a go test binary must resolve the test work factor")
}

// TestSealPassphraseStanzaCarriesWorkFactor proves Seal applies the
// package work factor to the passphrase arm instead of age's built-in one.
func TestSealPassphraseStanzaCarriesWorkFactor(t *testing.T) {
	raw := sealForTest(t, map[string]string{"K": "v"})
	assert.Equal(t, strconv.Itoa(scryptWorkFactor), scryptStanzaWorkFactor(t, raw))

	got, err := Open(raw, testMaterial)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"K": "v"}, got)
}

// TestSealPassphraseProductionWorkFactor seals once at the shipped work
// factor, so the production wiring is exercised end to end. It is the only
// test that pays the full scrypt cost.
func TestSealPassphraseProductionWorkFactor(t *testing.T) {
	orig := scryptWorkFactor
	scryptWorkFactor = scryptWorkFactorFor(false)
	t.Cleanup(func() { scryptWorkFactor = orig })

	raw, err := Seal(map[string]string{"K": "v"}, testMaterial)
	require.NoError(t, err)
	assert.Equal(t, "18", scryptStanzaWorkFactor(t, raw))
}
