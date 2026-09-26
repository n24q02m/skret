package keystore

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testMaterial = "unit-test-key-material"

// testIdentity is a real age X25519 private key (AGE-SECRET-KEY-1...)
// generated once per test binary; tests that need the X25519 arm use it.
var testIdentity = func() string {
	id, err := GenerateIdentity()
	if err != nil {
		panic(err)
	}
	return id
}()

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
	raw, err := Seal(secrets, testMaterial)
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

func TestSealOpenRoundTripX25519(t *testing.T) {
	// A real age private key material selects the X25519 arm: the file
	// carries an X25519 recipient stanza and decrypts with the same key.
	secrets := map[string]string{"API_KEY": "value-1", "DB_PASS": "s3cr3t"}
	raw, err := Seal(secrets, testIdentity)
	require.NoError(t, err)
	assert.True(t, Detect(raw))
	assert.Equal(t, "X25519", StanzaKind(raw))
	assert.NotContains(t, "scrypt", string(raw))

	got, err := Open(raw, testIdentity)
	require.NoError(t, err)
	assert.Equal(t, secrets, got)
}

func TestSealEnvelopeShape(t *testing.T) {
	raw := sealForTest(t, map[string]string{"K": "hunter2-plain-value"})
	s := string(raw)
	assert.True(t, Detect([]byte(s)))
	assert.Contains(t, s, Format, "age wire magic must be the first line")
	assert.Contains(t, s, "-> scrypt ", "passphrase material must produce a scrypt stanza")
	assert.NotContains(t, s, "hunter2-plain-value", "plaintext value must not appear")
	assert.NotContains(t, s, "unit-test-key-material", "key material must not appear")
}

func TestSealPayloadIsPlaintextFileShape(t *testing.T) {
	// The decrypted payload is a normal plaintext local file — so external
	// `age -d` output feeds any YAML reader.
	raw := sealForTest(t, map[string]string{"K": "v"})
	plain := decryptPayloadForTest(t, raw, testMaterial)
	assert.Contains(t, plain, "version: \"1\"")
	assert.Contains(t, plain, "secrets:")
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
	// Flip a payload byte: age authentication must reject the file.
	i := strings.LastIndex(string(raw), "\n")
	require.Greater(t, i, 0)
	b := append([]byte(nil), raw...)
	if b[i-1] == 'A' {
		b[i-1] = 'B'
	} else {
		b[i-1] = 'A'
	}
	_, err := Open(b, testMaterial)
	require.Error(t, err)
	assert.Equal(t, CodeAuthError, exitCodeOf(t, err))
}

func TestOpenX25519RejectsOtherIdentity(t *testing.T) {
	other, err := GenerateIdentity()
	require.NoError(t, err)
	raw, err := Seal(map[string]string{"K": "v"}, testIdentity)
	require.NoError(t, err)
	_, err = Open(raw, other)
	require.Error(t, err, "a different age identity must not decrypt")
	assert.Equal(t, CodeAuthError, exitCodeOf(t, err))
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
		{name: "legacy envelope", raw: string(func() []byte {
			raw, err := SealLegacy(map[string]string{"A": "b"}, testMaterial, nil)
			require.NoError(t, err)
			return raw
		}()), want: false},
		{name: "age envelope", raw: string(sealForTest(t, map[string]string{"A": "b"})), want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, Detect([]byte(tt.raw)))
		})
	}
}

func TestSealEmptyMaterial(t *testing.T) {
	_, err := Seal(map[string]string{"K": "v"}, "")
	require.Error(t, err)
	assert.Equal(t, CodeValidationError, exitCodeOf(t, err))
	_, err = Open([]byte("age-encryption.org/v1"), "")
	require.Error(t, err)
	assert.Equal(t, CodeValidationError, exitCodeOf(t, err))
}

func TestParseIdentityRejectsNonAgeKey(t *testing.T) {
	_, err := ParseIdentity("not-an-age-key")
	require.Error(t, err)
	assert.Equal(t, CodeValidationError, exitCodeOf(t, err))
	assert.Contains(t, err.Error(), EnvKeyPrimary)

	id, err := ParseIdentity(testIdentity)
	require.NoError(t, err)
	assert.Equal(t, testIdentity, id.String())
}

func TestGenerateIdentityIsBech32AgeKey(t *testing.T) {
	key, err := GenerateIdentity()
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(key, "AGE-SECRET-KEY-1"), "age private keys are bech32 with the AGE-SECRET-KEY- HRP")
	assert.False(t, IsAgeIdentity("hunter2-passphrase"))
	assert.True(t, IsAgeIdentity(key))
	assert.Equal(t, "X25519", RecipientKind(key))
	assert.Equal(t, "scrypt", RecipientKind("hunter2-passphrase"))
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

func TestResolveIdentityPrefersAgeKeys(t *testing.T) {
	tests := []struct {
		name       string
		primary    string
		fallback   string
		keyring    string
		wantSource string
	}{
		{name: "age key in primary env", primary: testIdentity, keyring: "legacy-raw", wantSource: "env:" + EnvKeyPrimary},
		{name: "age key in fallback env", fallback: testIdentity, keyring: "legacy-raw", wantSource: "env:" + EnvKeyFallback},
		{name: "age key in keyring", keyring: testIdentity, wantSource: SourceKeyring},
		{name: "non-age env falls back to passphrase arm", primary: "legacy-raw", keyring: testIdentity, wantSource: "env:" + EnvKeyPrimary},
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

			res, err := ResolveIdentity(ResolveOpts{Interactive: false})
			require.NoError(t, err)
			assert.Equal(t, tt.wantSource, res.Source)
		})
	}
}

func TestResolveIdentityNonInteractiveFailsWithHint(t *testing.T) {
	t.Setenv(EnvKeyPrimary, "")
	t.Setenv(EnvKeyFallback, "")
	injectKeyring(t, map[string]string{}, nil, nil)

	_, err := ResolveIdentity(ResolveOpts{Interactive: false})
	require.Error(t, err)
	assert.Equal(t, CodeAuthError, exitCodeOf(t, err))
	assert.Contains(t, remediationOf(err), EnvKeyPrimary)
	assert.Contains(t, remediationOf(err), "AGE-SECRET-KEY")
}

func TestGenerateAndStoreKeyring(t *testing.T) {
	store := map[string]string{}
	injectKeyring(t, store, nil, nil)

	key, err := GenerateIdentity()
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(key, "AGE-SECRET-KEY-1"), "generated key must be a bech32 age private key")
	require.True(t, IsAgeIdentity(key))

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
	legacyPath := filepath.Join(dir, "legacy.yaml")
	legacyRaw, err := SealLegacy(map[string]string{"A": "b"}, testMaterial, nil)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(legacyPath, legacyRaw, 0o600))
	missingPath := filepath.Join(dir, "missing.yaml")

	tests := []struct {
		name          string
		path          string
		cfgEncrypted  bool
		withKey       bool
		wantEncrypted bool
		wantFormat    string
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
			name:          "age file",
			path:          encPath,
			cfgEncrypted:  true,
			withKey:       true,
			wantEncrypted: true,
			wantFormat:    Format,
			wantKDF:       "scrypt",
			wantKeyAvail:  true,
		},
		{
			name:          "age file without key warns",
			path:          encPath,
			withKey:       false,
			wantEncrypted: true,
			wantFormat:    Format,
			wantKDF:       "scrypt",
			wantWarnKey:   "no key material",
		},
		{
			name:          "legacy file reports legacy format and kdf",
			path:          legacyPath,
			withKey:       true,
			wantEncrypted: true,
			wantFormat:    FormatLegacy,
			wantKDF:       "argon2id",
			wantKeyAvail:  true,
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
			assert.Equal(t, tt.wantFormat, st.Format)
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
