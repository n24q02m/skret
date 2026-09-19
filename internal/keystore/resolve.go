package keystore

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math"
	"os"
	"sort"

	"github.com/zalando/go-keyring"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

// Source names reported for resolved key material.
const (
	SourceEnv     = "env"
	SourceKeyring = "keyring"
	SourcePassphr = "passphrase"
)

// ResolveOpts controls key-material resolution.
type ResolveOpts struct {
	// Interactive allows falling through to a terminal passphrase prompt.
	// Callers MUST pass false in non-interactive contexts (CI, scripts,
	// piped stdin): the prompt is then skipped and resolution fails with
	// an actionable remediation instead of blocking.
	Interactive bool
}

// Result carries the resolved key material plus provenance for display.
// Material is never logged or printed by skret itself.
type Result struct {
	Material string
	Source   string
}

// keyringGet / keyringSet are vars for test injection (OS keyrings are
// unavailable on headless CI).
var (
	keyringGet = keyring.Get
	keyringSet = keyring.Set
	// readPassword reads a passphrase without echo. Overridable in tests.
	readPassword = func(prompt string) (string, error) {
		fmt.Fprint(os.Stderr, prompt)
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
)

// ResolveKeyMaterial finds decryption/encryption key material in precedence
// order: SKRET_AGE_KEY → SKRET_LOCAL_KEY → OS keyring → (interactive only)
// passphrase prompt. Non-interactive without env/keyring material fails with
// AuthError and a remediation hint.
func ResolveKeyMaterial(opts ResolveOpts) (*Result, error) {
	for _, name := range []string{EnvKeyPrimary, EnvKeyFallback} {
		if v := os.Getenv(name); v != "" {
			return &Result{Material: v, Source: SourceEnv + ":" + name}, nil
		}
	}
	if v, err := keyringGet(KeyringService, KeyringUser); err == nil && v != "" {
		return &Result{Material: v, Source: SourceKeyring}, nil
	}
	if !opts.Interactive {
		return nil, noKeyMaterial(fmt.Sprintf(
			"set %s or %s, or run %q on a machine with an OS keyring",
			EnvKeyPrimary, EnvKeyFallback, "skret keys init"))
	}
	pw, err := promptPassphraseConfirm()
	if err != nil {
		return nil, err
	}
	return &Result{Material: pw, Source: SourcePassphr}, nil
}

// promptPassphraseConfirm asks for a passphrase twice and requires the
// entries to match. Never used unless ResolveOpts.Interactive was set.
func promptPassphraseConfirm() (string, error) {
	a, err := readPassword("Enter passphrase: ")
	if err != nil {
		return "", newError(CodeAuthError, "keys: read passphrase", err)
	}
	if a == "" {
		return "", newError(CodeValidationError, "keys: passphrase must not be empty", nil)
	}
	b, err := readPassword("Confirm passphrase: ")
	if err != nil {
		return "", newError(CodeAuthError, "keys: read passphrase confirmation", err)
	}
	if a != b {
		return "", newError(CodeValidationError, "keys: passphrases do not match", nil)
	}
	return a, nil
}

// GenerateKey returns 32 bytes of CSPRNG entropy, base64-encoded — the value
// stored in the OS keyring by `skret keys init`.
func GenerateKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", newError(CodeGenericError, "keys: generate key", err)
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// StoreKeyring writes key material to the OS keyring and verifies the write
// round-trips (some backends silently drop writes — see internal/auth).
func StoreKeyring(material string) error {
	if err := keyringSet(KeyringService, KeyringUser, material); err != nil {
		return newError(CodeAuthError, "keys: store key in OS keyring", err)
	}
	got, err := keyringGet(KeyringService, KeyringUser)
	if err != nil || got != material {
		return newError(CodeAuthError, "keys: OS keyring did not round-trip the key", err)
	}
	return nil
}

// Status is the encryption-state report for one local provider file.
// Values are never included — only key names in warnings.
type Status struct {
	Encrypted    bool     `json:"encrypted"`
	Format       string   `json:"format,omitempty"`
	KDF          string   `json:"kdf,omitempty"`
	EncryptedCfg bool     `json:"encrypted_config"` // `encrypted: true` declared in .skret.yaml (write intent)
	KeyAvailable bool     `json:"key_available"`
	KeySource    string   `json:"key_source,omitempty"`
	Warnings     []string `json:"warnings,omitempty"`
}

// StatusOf reports the encryption state of filePath. A missing file is
// reported as not encrypted with no error (nothing to decrypt yet).
// cfgEncrypted is the `encrypted` flag from the active environment config;
// it describes write intent, while Encrypted describes on-disk reality.
func StatusOf(filePath string, cfgEncrypted bool) (*Status, error) {
	st := &Status{EncryptedCfg: cfgEncrypted, Warnings: []string{}}
	raw, err := os.ReadFile(filePath)
	switch {
	case err == nil:
		if Detect(raw) {
			st.Encrypted = true
			st.Format = Format
			var env envelope
			if yaml.Unmarshal(raw, &env) == nil {
				st.KDF = env.KDF.Algorithm
			}
		} else {
			st.Warnings = append(st.Warnings, plaintextEntropyWarnings(raw)...)
		}
	case os.IsNotExist(err):
		// No file yet: nothing to report beyond config intent.
	default:
		return nil, newError(CodeConfigError,
			fmt.Sprintf("keys: read %q", filePath), err)
	}

	res, resErr := ResolveKeyMaterial(ResolveOpts{Interactive: false})
	if resErr == nil {
		st.KeyAvailable = true
		st.KeySource = res.Source
	}
	if st.Encrypted && !st.KeyAvailable {
		st.Warnings = append(st.Warnings,
			"file is encrypted but no key material is available non-interactively")
	}
	if !st.Encrypted && len(st.Warnings) > 0 {
		st.Warnings = append(st.Warnings,
			"file holds high-entropy plaintext values; consider `skret keys init --encrypt-existing`")
	}
	return st, nil
}

// entropyMinLength / entropyThreshold define the high-entropy heuristic:
// values at least 16 chars whose per-character Shannon entropy is >= 4.0
// bits look like generated credentials (API keys, tokens), not prose
// (~2-3.5 bits). Deliberately conservative: this only drives a warning.
const (
	entropyMinLength = 16
	entropyThreshold = 4.0
)

// plaintextEntropyWarnings parses a plaintext local-provider file and
// returns one warning per secret key whose value looks machine-generated.
// Key names only; values never leave this function.
func plaintextEntropyWarnings(raw []byte) []string {
	var f struct {
		Secrets map[string]string `yaml:"secrets"`
	}
	if yaml.Unmarshal(raw, &f) != nil {
		return nil
	}
	keys := make([]string, 0, len(f.Secrets))
	for k, v := range f.Secrets {
		if len(v) >= entropyMinLength && ShannonBits(v) >= entropyThreshold {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	warnings := make([]string, 0, len(keys))
	for _, k := range keys {
		warnings = append(warnings, fmt.Sprintf("key %q looks like a high-entropy credential stored in plaintext", k))
	}
	return warnings
}

// ShannonBits returns the per-character Shannon entropy of s in bits
// (0 for the empty string).
func ShannonBits(s string) float64 {
	if s == "" {
		return 0
	}
	counts := make(map[rune]int)
	for _, r := range s {
		counts[r]++
	}
	var bits float64
	n := float64(len([]rune(s)))
	for _, c := range counts {
		p := float64(c) / n
		bits -= p * math.Log2(p)
	}
	return bits
}
