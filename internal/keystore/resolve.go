package keystore

import (
	"errors"
	"fmt"
	"math"
	"os"
	"sort"

	"filippo.io/age"
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
//
// This is the raw-material resolver used for legacy (skret-encrypted-v1)
// files and sync-state hash derivation. Standard age files resolve through
// ResolveIdentity instead.
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

// ResolveIdentity resolves age-usable key material for standard age files.
// Source precedence matches ResolveKeyMaterial exactly (SKRET_AGE_KEY →
// SKRET_LOCAL_KEY → OS keyring → interactive passphrase): whatever value
// wins, an age private key drives the X25519 arm and any other value the
// passphrase (scrypt) arm — deterministic, so the material that decrypts a
// file also re-seals it.
func ResolveIdentity(opts ResolveOpts) (*Result, error) {
	res, err := ResolveKeyMaterial(opts)
	if err != nil {
		var e *Error
		if errors.As(err, &e) && e.Code == CodeAuthError {
			// Reword the hint for the age context; keep the canonical
			// "no key material available" prefix (exit-4 contract).
			return nil, &Error{
				Code:    CodeAuthError,
				Message: "keys: no key material available (age: set SKRET_AGE_KEY or SKRET_LOCAL_KEY, or run \"skret keys init\" on a machine with an OS keyring)",
				Hint:    fmt.Sprintf("export %s=<AGE-SECRET-KEY-1...>  # generate one with: age-keygen  (or run: skret keys init)", EnvKeyPrimary),
			}
		}
		return nil, err
	}
	return res, nil
}

// IsAgeIdentity reports whether s parses as an age X25519 private key
// (AGE-SECRET-KEY-1...).
func IsAgeIdentity(s string) bool {
	_, err := age.ParseX25519Identity(s)
	return err == nil
}

// KeyringMaterial returns the key material stored in the OS keyring by
// `skret keys init`, if any.
func KeyringMaterial() (string, bool) {
	v, err := keyringGet(KeyringService, KeyringUser)
	if err != nil || v == "" {
		return "", false
	}
	return v, true
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
// For encrypted files KDF reports the recipient side: the age stanza type
// ("X25519" or "scrypt") for age files, the legacy KDF ("argon2id") for
// pre-age envelopes.
func StatusOf(filePath string, cfgEncrypted bool) (*Status, error) {
	st := &Status{EncryptedCfg: cfgEncrypted, Warnings: []string{}}
	raw, err := os.ReadFile(filePath)
	switch {
	case err == nil:
		switch {
		case Detect(raw):
			st.Encrypted = true
			st.Format = Format
			st.KDF = StanzaKind(raw)
		case DetectLegacy(raw):
			st.Encrypted = true
			st.Format = FormatLegacy
			var env legacyEnvelope
			if yaml.Unmarshal(raw, &env) == nil {
				st.KDF = env.KDF.Algorithm
			}
		default:
			st.Warnings = append(st.Warnings, plaintextEntropyWarnings(raw)...)
		}
	case os.IsNotExist(err):
		// No file yet: nothing to report beyond config intent.
	default:
		return nil, newError(CodeConfigError,
			fmt.Sprintf("keys: read %q", filePath), err)
	}

	res, resErr := resolveForFormat(st.Format)(ResolveOpts{Interactive: false})
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

// resolveForFormat picks the key resolver matching the on-disk format:
// legacy envelopes were sealed with raw material, age files resolve an age
// identity (with the passphrase arm as fallback). Plaintext/missing files
// report the age resolver — that is what the next write would use.
func resolveForFormat(format string) func(ResolveOpts) (*Result, error) {
	if format == FormatLegacy {
		return ResolveKeyMaterial
	}
	return ResolveIdentity
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
