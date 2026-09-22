// Package keystore implements optional at-rest encryption for the local
// YAML provider: an argon2id-derived ChaCha20-Poly1305 envelope stored in
// place of plaintext secrets, key-material resolution (env → OS keyring →
// interactive passphrase), and StatusOf for reporting encryption state.
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

// Format is the marker stored in the envelope header. Its presence (as the
// yaml "format" field) is how an on-disk file is recognized as encrypted,
// independent of any config flag.
const Format = "skret-encrypted-v1"

// EnvKeyPrimary / EnvKeyFallback are the environment variables consulted for
// key material, in order. SKRET_AGE_KEY wins so the name stays stable if the
// implementation ever moves to an actual age keypair.
const (
	EnvKeyPrimary  = "SKRET_AGE_KEY"
	EnvKeyFallback = "SKRET_LOCAL_KEY"
)

// KeyringService / KeyringUser identify the OS keyring entry holding the
// generated local-encryption key (service "skret" matches internal/auth).
const (
	KeyringService = "skret"
	KeyringUser    = "local-enc-key"
)

// Default KDF parameters (argon2id). Stored per-envelope so they can evolve;
// these are the values Seal writes when creating a fresh envelope.
const (
	defaultArgonTime        = 3
	defaultArgonMemoryKiB   = 64 * 1024
	defaultArgonParallelism = 4
)

// kdfParams are the argon2id parameters recorded in an envelope header.
type kdfParams struct {
	Algorithm   string `yaml:"algorithm"`
	Salt        string `yaml:"salt"` // base64
	Time        uint32 `yaml:"time"`
	MemoryKiB   uint32 `yaml:"memory_kib"`
	Parallelism uint8  `yaml:"parallelism"`
}

// envelope is the on-disk shape of an encrypted local provider file. Secrets
// values are "v1:<b64 nonce>:<b64 ciphertext+tag>" with the secret key name
// bound as AEAD additional data. Meta carries non-secret per-key metadata
// (currently expiry timestamps) as plaintext: like the kdf header it holds
// nothing value-derived, and it must survive round trips without changing
// the ciphertext scheme.
type envelope struct {
	Version string            `yaml:"version"`
	Format  string            `yaml:"format"`
	KDF     kdfParams         `yaml:"kdf"`
	Secrets map[string]string `yaml:"secrets"`
	Meta    map[string]string `yaml:"meta,omitempty"`
}

// Detect reports whether raw looks like a keystore envelope. It never
// errors: unknown bytes are simply "not encrypted".
func Detect(raw []byte) bool {
	var probe struct {
		Format string `yaml:"format"`
	}
	if yaml.Unmarshal(raw, &probe) != nil {
		return false
	}
	return probe.Format == Format
}

// Seal encrypts secrets into envelope bytes using keyMaterial. params may be
// nil to use defaults; otherwise it is cloned (the salt is always fresh).
// AAD binding: each ciphertext is bound to its key name, so values cannot be
// swapped between keys without detection.
func Seal(secrets map[string]string, keyMaterial string, params *kdfParams) ([]byte, error) {
	return SealWithMeta(secrets, nil, keyMaterial, params)
}

// SealWithMeta is Seal plus plaintext per-key metadata stored in the
// envelope header. A nil/empty meta produces byte-identical output to Seal.
func SealWithMeta(secrets map[string]string, meta map[string]string, keyMaterial string, params *kdfParams) ([]byte, error) {
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

	aead, err := aeadFor(keyMaterial, p)
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

	raw, err := yaml.Marshal(&envelope{
		Version: "1",
		Format:  Format,
		KDF:     *p,
		Secrets: encoded,
		Meta:    meta,
	})
	if err != nil {
		return nil, newError(CodeGenericError, "keystore: marshal envelope", err)
	}
	return raw, nil
}

// Open decrypts an envelope previously written by Seal. Wrong key material
// or tampered bytes return an AuthError carrying an actionable hint.
func Open(raw []byte, keyMaterial string) (map[string]string, error) {
	secrets, _, err := OpenWithMeta(raw, keyMaterial)
	return secrets, err
}

// OpenWithMeta is Open plus the envelope's per-key metadata map (nil when
// the envelope predates metadata or carries none).
func OpenWithMeta(raw []byte, keyMaterial string) (map[string]string, map[string]string, error) {
	var env envelope
	if err := yaml.Unmarshal(raw, &env); err != nil {
		return nil, nil, newError(CodeConfigError, "keystore: parse envelope", err)
	}
	if env.Format != Format {
		return nil, nil, newError(CodeConfigError,
			fmt.Sprintf("keystore: unsupported envelope format %q (expected %q)", env.Format, Format), nil)
	}
	aead, err := aeadFor(keyMaterial, &env.KDF)
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
		if !found2 {
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
				"verify SKRET_AGE_KEY/SKRET_LOCAL_KEY matches the key created by `skret keys init`")
		}
		secrets[k] = string(pt)
	}
	return secrets, env.Meta, nil
}

// aeadFor derives the argon2id key from keyMaterial + params and returns the
// XChaCha20-Poly1305 AEAD.
func aeadFor(keyMaterial string, p *kdfParams) (cipher.AEAD, error) {
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
