// Legacy skret-encrypted-v1 envelope: argon2id-derived XChaCha20-Poly1305
// per-value encryption, replaced by the standard age format (keystore.go).
// Kept for exactly three purposes, never for new envelopes by choice:
//  1. reads of files not yet migrated (provider auto-detect),
//  2. the one-command migration in `skret keys init --encrypt-existing`,
//  3. format-preserving writes to a not-yet-migrated file, so a legacy
//     file stays decryptable with its existing material until the owner
//     runs the migration.
package keystore

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"gopkg.in/yaml.v3"
)

// FormatLegacy is the marker stored in the legacy envelope header. Its
// presence (as the yaml "format" field) is how an on-disk file is
// recognized as a pre-age envelope.
const FormatLegacy = "skret-encrypted-v1"

// Default KDF parameters (argon2id). Stored per-envelope so they can evolve;
// these are the values SealLegacy writes when creating a fresh envelope.
const (
	defaultArgonTime        = 3
	defaultArgonMemoryKiB   = 64 * 1024
	defaultArgonParallelism = 4
)

// kdfParams are the argon2id parameters recorded in a legacy envelope header.
type kdfParams struct {
	Algorithm   string `yaml:"algorithm"`
	Salt        string `yaml:"salt"` // base64
	Time        uint32 `yaml:"time"`
	MemoryKiB   uint32 `yaml:"memory_kib"`
	Parallelism uint8  `yaml:"parallelism"`
}

// legacyEnvelope is the on-disk shape of a legacy encrypted local provider
// file. Secrets values are "v1:<b64 nonce>:<b64 ciphertext+tag>" with the
// secret key name bound as AEAD additional data. Meta carries non-secret
// per-key metadata (expiry timestamps) as plaintext.
type legacyEnvelope struct {
	Version string            `yaml:"version"`
	Format  string            `yaml:"format"`
	KDF     kdfParams         `yaml:"kdf"`
	Secrets map[string]string `yaml:"secrets"`
	Meta    map[string]string `yaml:"meta,omitempty"`
}

// DetectLegacy reports whether raw looks like a legacy keystore envelope.
// Age files are not YAML, so the two detectors are mutually exclusive.
func DetectLegacy(raw []byte) bool {
	var probe struct {
		Format string `yaml:"format"`
	}
	if yaml.Unmarshal(raw, &probe) != nil {
		return false
	}
	return probe.Format == FormatLegacy
}

// SealLegacy encrypts secrets into a legacy v1 envelope (transitional
// format-preserving writes only; new envelopes use Seal).
func SealLegacy(secrets map[string]string, keyMaterial string, params *kdfParams) ([]byte, error) {
	return SealLegacyWithMeta(secrets, nil, keyMaterial, params)
}

// SealLegacyWithMeta is SealLegacy plus plaintext per-key metadata stored in
// the envelope header.
func SealLegacyWithMeta(secrets map[string]string, meta map[string]string, keyMaterial string, params *kdfParams) ([]byte, error) {
	if keyMaterial == "" {
		return nil, newError(CodeValidationError, "keystore: key material is empty", nil)
	}
	p := defaultKDFParams()
	if params != nil {
		clone := *params
		p = &clone
	}
	if p.Salt == "" {
		salt := make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			return nil, newError(CodeGenericError, "keystore: generate salt", err)
		}
		p.Salt = base64.StdEncoding.EncodeToString(salt)
	}

	aead, err := legacyAeadFor(keyMaterial, p)
	if err != nil {
		return nil, err
	}

	encoded := make(map[string]string, len(secrets))
	for k, v := range secrets {
		nonce := make([]byte, chacha20poly1305.NonceSizeX)
		if _, err := rand.Read(nonce); err != nil {
			return nil, newError(CodeGenericError, "keystore: generate nonce", err)
		}
		// Seal with a nil dst so the blob is ciphertext+tag ONLY (the nonce
		// is stored separately); prepending would double-encode it.
		ct := aead.Seal(nil, nonce, []byte(v), []byte(k))
		encoded[k] = "v1:" +
			base64.StdEncoding.EncodeToString(nonce) + ":" +
			base64.StdEncoding.EncodeToString(ct)
	}

	raw, err := yaml.Marshal(&legacyEnvelope{
		Version: "1",
		Format:  FormatLegacy,
		KDF:     *p,
		Secrets: encoded,
		Meta:    meta,
	})
	if err != nil {
		return nil, newError(CodeGenericError, "keystore: marshal envelope", err)
	}
	return raw, nil
}

// OpenLegacy decrypts a legacy v1 envelope. Wrong key material or tampered
// bytes return an AuthError carrying an actionable hint.
func OpenLegacy(raw []byte, keyMaterial string) (map[string]string, error) {
	secrets, _, err := OpenLegacyWithMeta(raw, keyMaterial)
	return secrets, err
}

// OpenLegacyWithMeta is OpenLegacy plus the envelope's per-key metadata map
// (nil when the envelope predates metadata or carries none).
func OpenLegacyWithMeta(raw []byte, keyMaterial string) (map[string]string, map[string]string, error) {
	var env legacyEnvelope
	if err := yaml.Unmarshal(raw, &env); err != nil {
		return nil, nil, newError(CodeConfigError, "keystore: parse envelope", err)
	}
	if env.Format != FormatLegacy {
		return nil, nil, newError(CodeConfigError,
			fmt.Sprintf("keystore: unsupported envelope format %q (expected %q)", env.Format, FormatLegacy), nil)
	}
	aead, err := legacyAeadFor(keyMaterial, &env.KDF)
	if err != nil {
		return nil, nil, err
	}

	secrets := make(map[string]string, len(env.Secrets))
	for k, blob := range env.Secrets {
		version, rest, found1 := strings.Cut(blob, ":")
		if !found1 || version != "v1" {
			return nil, nil, newError(CodeConfigError,
				fmt.Sprintf("keystore: malformed ciphertext for key %q", k), nil)
		}
		nonceStr, ctStr, found2 := strings.Cut(rest, ":")
		if !found2 || ctStr == "" {
			return nil, nil, newError(CodeConfigError,
				fmt.Sprintf("keystore: malformed ciphertext for key %q", k), nil)
		}
		nonce, err := base64.StdEncoding.DecodeString(nonceStr)
		if err != nil {
			return nil, nil, newError(CodeConfigError, fmt.Sprintf("keystore: nonce for key %q", k), err)
		}
		ct, err := base64.StdEncoding.DecodeString(ctStr)
		if err != nil {
			return nil, nil, newError(CodeConfigError, fmt.Sprintf("keystore: ciphertext for key %q", k), err)
		}
		pt, err := aead.Open(nil, nonce, ct, []byte(k))
		if err != nil {
			return nil, nil, withRemediation(newError(CodeAuthError,
				"keystore: decrypt failed (wrong key material or tampered file)", err),
				"verify SKRET_AGE_KEY/SKRET_LOCAL_KEY matches the key this file was encrypted with, then run `skret keys init --encrypt-existing` to migrate it to the age format")
		}
		secrets[k] = string(pt)
	}
	return secrets, env.Meta, nil
}

// legacyAeadFor derives the argon2id key from keyMaterial + params and
// returns the XChaCha20-Poly1305 AEAD.
func legacyAeadFor(keyMaterial string, p *kdfParams) (cipher.AEAD, error) {
	if p.Algorithm != "argon2id" && p.Algorithm != "" {
		return nil, newError(CodeConfigError,
			fmt.Sprintf("keystore: unsupported kdf algorithm %q", p.Algorithm), nil)
	}
	salt, err := base64.StdEncoding.DecodeString(p.Salt)
	if err != nil || len(salt) < 8 {
		return nil, newError(CodeConfigError, "keystore: invalid kdf salt", err)
	}
	key := argon2.IDKey([]byte(keyMaterial), salt, p.Time, p.MemoryKiB, p.Parallelism, 32)
	return chacha20poly1305.NewX(key)
}

func defaultKDFParams() *kdfParams {
	return &kdfParams{
		Algorithm:   "argon2id",
		Time:        defaultArgonTime,
		MemoryKiB:   defaultArgonMemoryKiB,
		Parallelism: defaultArgonParallelism,
	}
}
