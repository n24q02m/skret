package keystore

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestErrorMessageAndUnwrap(t *testing.T) {
	inner := errors.New("boom")
	err := newError(CodeConfigError, "parse failed", inner)

	assert.Equal(t, "parse failed: boom", err.Error())
	assert.Equal(t, inner, err.Unwrap())
	assert.Same(t, inner, errors.Unwrap(err))

	assert.Equal(t, "bare", newError(CodeConfigError, "bare", nil).Error())
}

func TestWithRemediation(t *testing.T) {
	// Attaching to a keystore error mutates it in place.
	base := newError(CodeAuthError, "no key", nil)
	out := withRemediation(base, "run keys init")
	assert.Same(t, base, out.(*Error))
	assert.Equal(t, "run keys init", base.Hint)

	// Non-keystore errors get wrapped generically so the hint survives.
	plain := errors.New("plain failure")
	wrapped := withRemediation(plain, "do X")
	var coder interface{ Remediation() string }
	require.True(t, errors.As(wrapped, &coder))
	assert.Equal(t, "do X", coder.Remediation())
	assert.Equal(t, CodeGenericError, exitCodeOf(t, wrapped))

	assert.Nil(t, withRemediation(nil, "hint"))
	assert.Same(t, plain, withRemediation(plain, ""))
}

func TestNoKeyMaterialError(t *testing.T) {
	err := noKeyMaterial("unit")
	assert.Equal(t, CodeAuthError, err.Code)
	assert.Contains(t, err.Message, "unit")
	assert.Contains(t, err.Hint, EnvKeyPrimary)
}

func TestOpenMalformedEnvelope(t *testing.T) {
	sealed := string(sealForTest(t, map[string]string{"K1": "v1", "K2": "v2"}))
	rewrap := func(mutate func(env *envelope)) []byte {
		var env envelope
		require.NoError(t, yaml.Unmarshal([]byte(sealed), &env))
		mutate(&env)
		raw, err := yaml.Marshal(&env)
		require.NoError(t, err)
		return raw
	}

	tests := []struct {
		name    string
		raw     []byte
		errCode int
		wantMsg string
	}{
		{
			name:    "not yaml",
			raw:     []byte("\x00\x01"),
			errCode: CodeConfigError,
			wantMsg: "parse envelope",
		},
		{
			name: "unknown format",
			raw: rewrap(func(env *envelope) {
				env.Format = "future-format"
			}),
			errCode: CodeConfigError,
			wantMsg: "unsupported envelope format",
		},
		{
			name: "unsupported kdf",
			raw: rewrap(func(env *envelope) {
				env.KDF.Algorithm = "bcrypt"
			}),
			errCode: CodeConfigError,
			wantMsg: "unsupported kdf algorithm",
		},
		{
			name: "salt not base64",
			raw: rewrap(func(env *envelope) {
				env.KDF.Salt = "!!!not base64!!!"
			}),
			errCode: CodeConfigError,
			wantMsg: "invalid kdf salt",
		},
		{
			name: "salt too short",
			raw: rewrap(func(env *envelope) {
				env.KDF.Salt = "YWJj" // "abc"
			}),
			errCode: CodeConfigError,
			wantMsg: "invalid kdf salt",
		},
		{
			name: "malformed blob",
			raw: rewrap(func(env *envelope) {
				env.Secrets["K1"] = "v9:broken"
			}),
			errCode: CodeConfigError,
			wantMsg: "malformed ciphertext",
		},
		{
			name: "blob wrong version tag",
			raw: rewrap(func(env *envelope) {
				env.Secrets["K1"] = "v2:AAAA:AAAA"
			}),
			errCode: CodeConfigError,
			wantMsg: "malformed ciphertext",
		},
		{
			name: "missing ciphertext",
			raw: rewrap(func(env *envelope) {
				env.Secrets["K1"] = "v1:AAAA"
			}),
			errCode: CodeConfigError,
			wantMsg: "malformed ciphertext",
		},
		{
			name: "nonce not base64",
			raw: rewrap(func(env *envelope) {
				env.Secrets["K1"] = "v1:@@@:AAAA"
			}),
			errCode: CodeConfigError,
			wantMsg: "nonce",
		},
		{
			name: "ciphertext not base64",
			raw: rewrap(func(env *envelope) {
				env.Secrets["K1"] = "v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAA:@@@"
			}),
			errCode: CodeConfigError,
			wantMsg: "ciphertext",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Open(tt.raw, testMaterial)
			require.Error(t, err)
			assert.Equal(t, tt.errCode, exitCodeOf(t, err))
			assert.Contains(t, err.Error(), tt.wantMsg)
		})
	}
}

func TestSealExplicitParams(t *testing.T) {
	// Explicit params (including a caller-provided salt) must be honored
	// and produce an envelope that opens with the same material.
	p := &kdfParams{
		Algorithm:   "argon2id",
		Salt:        "MDEyMzQ1Njc4OWFiY2RlZg==", // 16 bytes: "0123456789abcdef"
		Time:        1,
		MemoryKiB:   8 * 1024,
		Parallelism: 2,
	}
	raw, err := Seal(map[string]string{"K": "v"}, testMaterial, p)
	require.NoError(t, err)
	secrets, err := Open(raw, testMaterial)
	require.NoError(t, err)
	assert.Equal(t, "v", secrets["K"])

	var env envelope
	require.NoError(t, yaml.Unmarshal(raw, &env))
	assert.Equal(t, p.Salt, env.KDF.Salt, "provided salt must be reused")
	assert.Equal(t, uint32(1), env.KDF.Time)
}

func TestPromptPassphraseReadError(t *testing.T) {
	orig := readPassword
	readPassword = func(string) (string, error) { return "", errors.New("tty gone") }
	t.Cleanup(func() { readPassword = orig })

	_, err := ResolveKeyMaterial(ResolveOpts{Interactive: true})
	require.Error(t, err)
	assert.Equal(t, CodeAuthError, exitCodeOf(t, err))
}

func TestKeyringSetError(t *testing.T) {
	injectKeyring(t, map[string]string{}, errors.New("keyring locked"), nil)
	_, err := GenerateKey()
	require.NoError(t, err)
	assert.Error(t, StoreKeyring("material"))
}

func TestStatusOfReadError(t *testing.T) {
	dir := t.TempDir()
	// A directory at the file path makes os.ReadFile fail with a non-NotExist error.
	path := filepath.Join(dir, "blocked.yaml")
	require.NoError(t, os.Mkdir(path, 0o700))

	_, err := StatusOf(path, false)
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "keys: read"), "read errors must be surfaced")
}
