package keystore

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

const testMaterial = "unit-test-key-material"

// exitCodeOf asserts the error implements the interface pkg/skret.ExitCode
// recognizes and returns its code — proving the contract without importing
// pkg/skret (which would cycle through provider/local).
func exitCodeOf(t *testing.T, err error) int {
	t.Helper()
	var c interface{ ExitCode() int }
	require.True(t, errors.As(err, &c), "error must implement ExitCode() int")
	return c.ExitCode()
}

// remediationOf mirrors pkg/skret.RemediationOf via its interface.
func remediationOf(err error) string {
	var r interface{ Remediation() string }
	if errors.As(err, &r) {
		return r.Remediation()
	}
	return ""
}

func sealForTest(t *testing.T, secrets map[string]string) []byte {
	t.Helper()
	raw, err := Seal(secrets, testMaterial, nil)
	require.NoError(t, err)
	return raw
}

func TestSealOpenRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		secrets map[string]string
	}{
		{name: "single", secrets: map[string]string{"API_KEY": "value-1"}},
		{name: "multiple", secrets: map[string]string{"A": "1", "B": "2", "C": "3"}},
		{name: "empty", secrets: map[string]string{}},
		{name: "unicode value", secrets: map[string]string{"NOTE": "pässwörd→🔑"}},
		{name: "multiline value", secrets: map[string]string{"PEM": "-----BEGIN\nLINE1\nLINE2\n-----END"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := sealForTest(t, tt.secrets)
			assert.True(t, Detect(raw), "sealed bytes must be detected as envelope")

			got, err := Open(raw, testMaterial)
			require.NoError(t, err)
			assert.Equal(t, tt.secrets, got)
		})
	}
}

func TestSealEnvelopeShape(t *testing.T) {
	raw := sealForTest(t, map[string]string{"K": "hunter2-plain-value"})
	s := string(raw)
	assert.Contains(t, s, "format: "+Format)
	assert.Contains(t, s, "algorithm: argon2id")
	assert.Contains(t, s, "version: \"1\"")
	assert.NotContains(t, s, "hunter2-plain-value", "plaintext value must not appear")
}

func TestOpenWrongKey(t *testing.T) {
	raw := sealForTest(t, map[string]string{"K": "v"})
	_, err := Open(raw, "wrong-material")
	require.Error(t, err)
	assert.Equal(t, CodeAuthError, exitCodeOf(t, err), "wrong key must map to exit code 4")
	assert.Contains(t, remediationOf(err), "SKRET_AGE_KEY")
}

func TestOpenTampered(t *testing.T) {
	raw := sealForTest(t, map[string]string{"K": "v"})
	// Corrupt the last byte of the yaml (inside the ciphertext blob region).
	i := strings.LastIndex(string(raw), ":")
	require.Greater(t, i, 0)
	b := append([]byte(nil), raw...)
	b[i+1] ^= 0x01
	_, err := Open(b, testMaterial)
	require.Error(t, err)
	assert.Equal(t, CodeAuthError, exitCodeOf(t, err))
}

func TestOpenAADSwapRejected(t *testing.T) {
	// Swapping ciphertext blobs between key names must fail: each blob is
	// AEAD-bound to its key name as additional data.
	raw := sealForTest(t, map[string]string{"K1": "v1", "K2": "v2"})
	var env envelope
	require.NoError(t, yaml.Unmarshal(raw, &env))
	require.Len(t, env.Secrets, 2)
	env.Secrets["K1"], env.Secrets["K2"] = env.Secrets["K2"], env.Secrets["K1"]

	resealed, err := yaml.Marshal(&env)
	require.NoError(t, err)
	_, err = Open(resealed, testMaterial)
	assert.Error(t, err, "swapped ciphertexts must not decrypt")
}

func TestDetect(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want bool
	}{
		{name: "plaintext yaml", raw: "version: \"1\"\nsecrets:\n  A: b\n", want: false},
		{name: "garbage", raw: "\x00\x01not yaml at all [", want: false},
		{name: "empty", raw: "", want: false},
		{name: "envelope", raw: string(sealForTest(t, map[string]string{"A": "b"})), want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, Detect([]byte(tt.raw)))
		})
	}
}

func TestSealEmptyMaterial(t *testing.T) {
	_, err := Seal(map[string]string{"K": "v"}, "", nil)
	require.Error(t, err)
	assert.Equal(t, CodeValidationError, exitCodeOf(t, err))
}

// injectKeyring swaps the keyring function vars for the duration of tt.
func injectKeyring(t *testing.T, store map[string]string, setErr, getErr error) {
	t.Helper()
	origGet, origSet := keyringGet, keyringSet
	keyringGet = func(service, user string) (string, error) {
		if getErr != nil {
			return "", getErr
		}
		v, ok := store[service+"\x00"+user]
		if !ok {
			return "", errKeyringNotFound
		}
		return v, nil
	}
	keyringSet = func(service, user, value string) error {
		if setErr != nil {
			return setErr
		}
		store[service+"\x00"+user] = value
		return nil
	}
	t.Cleanup(func() { keyringGet, keyringSet = origGet, origSet })
}

// errKeyringNotFound mirrors keyring.ErrNotFound without importing go-keyring
// semantics into every test.
var errKeyringNotFound = &simpleErr{"secret not found"}

type simpleErr struct{ msg string }

func (e *simpleErr) Error() string { return e.msg }

func TestResolveKeyMaterialOrder(t *testing.T) {
	tests := []struct {
		name          string
		primary       string
		fallback      string
		keyring       string
		interactive   bool
		promptReturns []string // readPassword stub results
		wantSource    string
		wantErrCode   int
		wantRemediate bool
	}{
		{name: "env primary wins over keyring", primary: "p", keyring: "k", wantSource: "env:" + EnvKeyPrimary},
		{name: "env fallback", fallback: "f", keyring: "k", wantSource: "env:" + EnvKeyFallback},
		{name: "keyring when no env", keyring: "k", wantSource: SourceKeyring},
		{
			name:          "non-interactive without sources errors",
			wantErrCode:   CodeAuthError,
			wantRemediate: true,
		},
		{
			name:          "interactive prompts",
			interactive:   true,
			promptReturns: []string{"hunter2", "hunter2"},
			wantSource:    SourcePassphr,
		},
		{
			name:          "interactive mismatch",
			interactive:   true,
			promptReturns: []string{"a", "b"},
			wantErrCode:   CodeValidationError,
		},
		{
			name:          "interactive empty",
			interactive:   true,
			promptReturns: []string{"", ""},
			wantErrCode:   CodeValidationError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.primary != "" {
				t.Setenv(EnvKeyPrimary, tt.primary)
			}
			if tt.fallback != "" {
				t.Setenv(EnvKeyFallback, tt.fallback)
			}
			store := map[string]string{}
			if tt.keyring != "" {
				store[KeyringService+"\x00"+KeyringUser] = tt.keyring
			}
			injectKeyring(t, store, nil, nil)

			origPrompt := readPassword
			prompts := tt.promptReturns
			readPassword = func(string) (string, error) {
				if len(prompts) == 0 {
					return "", &simpleErr{"unexpected prompt"}
				}
				p := prompts[0]
				prompts = prompts[1:]
				return p, nil
			}
			t.Cleanup(func() { readPassword = origPrompt })

			res, err := ResolveKeyMaterial(ResolveOpts{Interactive: tt.interactive})
			if tt.wantErrCode != 0 {
				require.Error(t, err)
				assert.Equal(t, tt.wantErrCode, exitCodeOf(t, err))
				if tt.wantRemediate {
					assert.Contains(t, remediationOf(err), EnvKeyPrimary)
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantSource, res.Source)
			switch {
			case tt.primary != "":
				assert.Equal(t, tt.primary, res.Material)
			case tt.fallback != "":
				assert.Equal(t, tt.fallback, res.Material)
			case tt.keyring != "":
				assert.Equal(t, tt.keyring, res.Material)
			default:
				assert.Equal(t, "hunter2", res.Material)
			}
		})
	}
}

func TestGenerateAndStoreKeyring(t *testing.T) {
	store := map[string]string{}
	injectKeyring(t, store, nil, nil)

	key, err := GenerateKey()
	require.NoError(t, err)
	decoded, err := base64.StdEncoding.DecodeString(key)
	require.NoError(t, err)
	assert.Len(t, decoded, 32, "generated key must be 256 bits")

	require.NoError(t, StoreKeyring(key))
	assert.Equal(t, key, store[KeyringService+"\x00"+KeyringUser])

	// A keyring that accepts writes but drops them must be rejected: the
	// read-back here errors, so the store must surface the failure.
	injectKeyring(t, map[string]string{}, nil, errKeyringNotFound)
	assert.Error(t, StoreKeyring(key), "dropped write must fail the round-trip check")
}

func TestStatusOf(t *testing.T) {
	highEntropy := "kW9xP2vQ8mZ5#J7&R4tU6yB3nL0cD1f" // 31 distinct chars => ~4.95 bits
	plaintext := "version: \"1\"\nsecrets:\n  API_TOKEN: \"" + highEntropy + "\"\n  APP_MODE: \"development\"\n"
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.yaml")
	require.NoError(t, os.WriteFile(plainPath, []byte(plaintext), 0o600))
	encPath := filepath.Join(dir, "enc.yaml")
	require.NoError(t, os.WriteFile(encPath, sealForTest(t, map[string]string{"A": "b"}), 0o600))
	missingPath := filepath.Join(dir, "missing.yaml")

	tests := []struct {
		name          string
		path          string
		cfgEncrypted  bool
		withKey       bool
		wantEncrypted bool
		wantKDF       string
		wantWarnKey   string // expected substring of some warning ("" = none)
		wantKeyAvail  bool
	}{
		{
			name:         "plaintext with high-entropy value warns",
			path:         plainPath,
			withKey:      true,
			wantWarnKey:  "API_TOKEN",
			wantKeyAvail: true,
		},
		{
			name:         "plaintext without key",
			path:         plainPath,
			wantWarnKey:  "API_TOKEN",
			wantKeyAvail: false,
		},
		{
			name:          "encrypted file",
			path:          encPath,
			cfgEncrypted:  true,
			withKey:       true,
			wantEncrypted: true,
			wantKDF:       "argon2id",
			wantKeyAvail:  true,
		},
		{
			name:          "encrypted without key warns",
			path:          encPath,
			withKey:       false,
			wantEncrypted: true,
			wantKDF:       "argon2id",
			wantWarnKey:   "no key material",
		},
		{
			name: "missing file is not an error",
			path: missingPath,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.withKey {
				t.Setenv(EnvKeyPrimary, testMaterial)
			} else {
				t.Setenv(EnvKeyPrimary, "")
				t.Setenv(EnvKeyFallback, "")
			}
			injectKeyring(t, map[string]string{}, nil, nil)

			st, err := StatusOf(tt.path, tt.cfgEncrypted)
			require.NoError(t, err)
			assert.Equal(t, tt.wantEncrypted, st.Encrypted)
			assert.Equal(t, tt.cfgEncrypted, st.EncryptedCfg)
			assert.Equal(t, tt.wantKDF, st.KDF)
			assert.Equal(t, tt.wantKeyAvail, st.KeyAvailable)
			if tt.wantWarnKey == "" {
				assert.Empty(t, st.Warnings)
			} else {
				require.NotEmpty(t, st.Warnings)
				joined := strings.Join(st.Warnings, "\n")
				assert.Contains(t, joined, tt.wantWarnKey)
				assert.NotContains(t, joined, highEntropy, "warnings must never contain values")
			}
		})
	}
}

func TestShannonBits(t *testing.T) {
	tests := []struct {
		in   string
		want float64
	}{
		{"", 0},
		{"aaaa", 0},
		{"ab", 1},
		{"abab", 1},
		{"abcd", 2},
	}
	for _, tt := range tests {
		assert.InDelta(t, tt.want, ShannonBits(tt.in), 1e-9, "input %q", tt.in)
	}
	// A 31-symbol string with all distinct characters has log2(31) bits.
	assert.InDelta(t, 4.9542, ShannonBits("kW9xP2vQ8mZ5#J7&R4tU6yB3nL0cD1f"), 0.001)
}
