package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/term"
	"gopkg.in/yaml.v3"

	"github.com/n24q02m/skret/internal/config"
	"github.com/n24q02m/skret/internal/keystore"
	"github.com/n24q02m/skret/pkg/skret"
	"github.com/spf13/cobra"
)

// newKeysCmd builds the `skret keys` command tree: init seeds key material
// (and optionally migrates the local file), show reports encryption state.
func newKeysCmd(opts *GlobalOpts) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "keys",
		Short: "Manage local-file encryption keys",
		Long: `Manage encryption for the local provider file (.secrets.*.yaml).

Encrypted files use the standard age format (age-encryption.org/v1) and
decrypt with the external age/rage CLIs, not only with skret.

Key material resolution order (used by every command touching an encrypted
local file): SKRET_AGE_KEY, then SKRET_LOCAL_KEY, then the OS keyring
('skret keys init' seeds it), then — only when stdin is a terminal — an
interactive passphrase prompt. In non-interactive contexts (CI, scripts) a
missing key fails with exit code 4 and a remediation hint; it never prompts.`,
	}
	cmd.AddCommand(newKeysInitCmd(opts))
	cmd.AddCommand(newKeysShowCmd(opts))
	return cmd
}

// keysInitOpts holds `keys init` flag values.
type keysInitOpts struct {
	file            string
	encryptExisting bool
	passphraseStdin bool
	format          string
}

func newKeysInitCmd(opts *GlobalOpts) *cobra.Command {
	ko := &keysInitOpts{}
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Set up key material for local-file encryption",
		Long: `Set up key material used to encrypt the local provider file.

Precedence for sourcing the key:
  1. SKRET_AGE_KEY / SKRET_LOCAL_KEY already set — an age private key
     (AGE-SECRET-KEY-1...) uses the age X25519 arm; any other value is used
     as a passphrase (age scrypt arm). Nothing is stored.
  2. --passphrase-stdin — one passphrase line is read from stdin (scripted
     setups on machines without an OS keyring).
  3. OS keyring — existing material is reused; when none is stored, a fresh
     age X25519 keypair is generated and stored (service "skret", user
     "local-enc-key") and verified round-trip.
  4. Interactive passphrase prompt (confirm twice) — only when stdin is a
     terminal; never in non-interactive mode (exit 4 with a remediation hint).

The key material is never printed. With --encrypt-existing the local file is
converted to the standard age format (age-encryption.org/v1) in place
(atomic write, 0600): legacy skret-encrypted-v1 envelopes are decrypted and
re-encrypted with every value kept, and ` + "`encrypted: true`" + ` is recorded
for the active environment in .skret.yaml.`,
		Example: `  skret keys init
  skret keys init --encrypt-existing
  skret keys init --file=./.secrets.dev.yaml --encrypt-existing --format json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return ko.run(cmd, opts)
		},
	}
	cmd.Flags().StringVar(&ko.file, "file", "", "local provider file (default: file of the active environment in .skret.yaml)")
	cmd.Flags().BoolVar(&ko.encryptExisting, "encrypt-existing", false, "migrate the local file (plaintext or legacy envelope) to the standard age format in place")
	cmd.Flags().BoolVar(&ko.passphraseStdin, "passphrase-stdin", false, "read the passphrase from stdin (one line) instead of generating/storing a key")
	cmd.Flags().StringVar(&ko.format, "format", "table", "output format (table, json)")
	return cmd
}

// keyCand is one candidate source of key material, in precedence order.
type keyCand struct {
	material string
	source   string
}

// keysFileState classifies the on-disk local provider file.
type keysFileState int

const (
	keysFileMissing keysFileState = iota
	keysFilePlaintext
	keysFileAge
	keysFileLegacy
)

// keysFileStateOf classifies raw bytes from the local provider file.
func keysFileStateOf(raw []byte) keysFileState {
	switch {
	case keystore.Detect(raw):
		return keysFileAge
	case keystore.DetectLegacy(raw):
		return keysFileLegacy
	default:
		return keysFilePlaintext
	}
}

func (o *keysInitOpts) run(cmd *cobra.Command, opts *GlobalOpts) error {
	target, err := resolveKeysTarget(opts, o.file)
	if err != nil {
		return err
	}
	file, cfgPath, cfg, envName, encCfg := target.file, target.cfgPath, target.cfg, target.envName, target.encCfg

	result := keysInitResult{File: file, Format: keystore.Format}

	// Classify the on-disk file (migration verification only; plain init
	// never touches the file).
	state := keysFileMissing
	var raw []byte
	if o.encryptExisting {
		raw, err = os.ReadFile(file)
		switch {
		case err == nil:
			state = keysFileStateOf(raw)
		case errors.Is(err, os.ErrNotExist):
			// Nothing to migrate yet: first write under the flipped config
			// flag will produce an age envelope.
		default:
			return skret.NewError(skret.ExitConfigError,
				fmt.Sprintf("keys: read %q", file), err)
		}
	}

	// Resolve candidate key material: env → stdin passphrase → keyring →
	// prompt. Generation (fresh age X25519 identity into the OS keyring)
	// happens only when no candidate exists.
	cands, err := o.keyCandidates()
	if err != nil {
		return err
	}

	switch state {
	case keysFileAge:
		// Already a standard age file: verify the material still decrypts it.
		var mat keyCand
		var ok bool
		mat, ok = firstOpen(cands, func(material string) error {
			_, _, derr := keystore.OpenWithMeta(raw, material)
			return derr
		})
		if !ok {
			return skret.WithRemediation(
				skret.NewError(skret.ExitAuthError, "keys: could not decrypt the age-encrypted file with any available key material", nil),
				fmt.Sprintf("export %s=<AGE-SECRET-KEY-1...> (the key this file was encrypted with), or rerun with --passphrase-stdin < line", keystore.EnvKeyPrimary))
		}
		result.KeySource = mat.source
		result.FileEncrypted = true
		result.AlreadyEncrypted = true
		result.KDF = keystore.StanzaKind(raw)
	case keysFileLegacy:
		// One-command migration: open the legacy envelope, re-seal every
		// value (and per-key metadata) into the standard age format.
		var secrets, meta map[string]string
		_, ok := firstOpen(cands, func(material string) error {
			s, m, derr := keystore.OpenLegacyWithMeta(raw, material)
			if derr == nil {
				secrets, meta = s, m
			}
			return derr
		})
		if !ok {
			return skret.WithRemediation(
				skret.NewError(skret.ExitAuthError, "keys: could not decrypt the legacy skret-encrypted-v1 envelope with any available key material", nil),
				fmt.Sprintf("export %s (or %s) with the key material this file was encrypted with, then rerun", keystore.EnvKeyPrimary, keystore.EnvKeyFallback))
		}
		// The first candidate seals the new file: an age private key uses
		// the X25519 arm, anything else the passphrase (scrypt) arm — the
		// same material decrypts it again later.
		newMat := cands[0]
		sealed, serr := keystore.SealWithMeta(secrets, meta, newMat.material)
		if serr != nil {
			return serr
		}
		if werr := writeFileAtomically0600(file, sealed); werr != nil {
			return skret.NewError(skret.ExitGenericError,
				fmt.Sprintf("keys: write age-encrypted %q", file), werr)
		}
		result.KeySource = newMat.source
		result.KeyringStored = false
		result.FileEncrypted = true
		result.KDF = keystore.RecipientKind(newMat.material)
	default:
		// Plaintext file or no file yet: establish material; the file is
		// converted by --encrypt-existing here or sealed on the next write
		// under `encrypted: true`.
		newMat, generated, gerr := resolveOrCreate(cands)
		if gerr != nil {
			return gerr
		}
		result.KeySource = newMat.source
		result.KeyringStored = generated
		result.KDF = keystore.RecipientKind(newMat.material)

		if state == keysFilePlaintext {
			var f struct {
				Secrets *map[string]string `yaml:"secrets"`
				Meta    map[string]string  `yaml:"meta"`
			}
			if uerr := yaml.Unmarshal(raw, &f); uerr != nil {
				return skret.NewError(skret.ExitConfigError,
					fmt.Sprintf("keys: parse plaintext file %q", file), uerr)
			}
			secrets := map[string]string{}
			if f.Secrets != nil {
				secrets = *f.Secrets
			}
			sealed, serr := keystore.SealWithMeta(secrets, f.Meta, newMat.material)
			if serr != nil {
				return serr
			}
			if werr := writeFileAtomically0600(file, sealed); werr != nil {
				return skret.NewError(skret.ExitGenericError,
					fmt.Sprintf("keys: write age-encrypted %q", file), werr)
			}
			result.FileEncrypted = true
		}
	}

	if o.encryptExisting && cfg != nil && !encCfg {
		if uerr := updateConfigEncryptedFlag(cfg, cfgPath, envName); uerr != nil {
			return uerr
		}
		result.ConfigUpdated = true
	}

	reportKeysInit(cmd, o.format, result)
	return nil
}

// keyCandidates collects key material in precedence order without side
// effects: SKRET_AGE_KEY, SKRET_LOCAL_KEY, --passphrase-stdin, the OS
// keyring, and — only when nothing else exists and stdin is a terminal —
// the interactive passphrase prompt.
func (o *keysInitOpts) keyCandidates() ([]keyCand, error) {
	var cands []keyCand
	for _, name := range []string{keystore.EnvKeyPrimary, keystore.EnvKeyFallback} {
		if v := os.Getenv(name); v != "" {
			cands = append(cands, keyCand{v, keystore.SourceEnv + ":" + name})
		}
	}
	if o.passphraseStdin {
		pw, err := readPassphraseStdin()
		if err != nil {
			return nil, err
		}
		cands = append(cands, keyCand{pw, keystore.SourcePassphr})
	}
	if v, ok := keystore.KeyringMaterial(); ok {
		cands = append(cands, keyCand{v, keystore.SourceKeyring})
	}
	if len(cands) == 0 && term.IsTerminal(int(os.Stdin.Fd())) {
		res, err := keystore.ResolveKeyMaterial(keystore.ResolveOpts{Interactive: true})
		if err != nil {
			return nil, err
		}
		cands = append(cands, keyCand{res.Material, res.Source})
	}
	return cands, nil
}

// resolveOrCreate picks the first candidate or, when none exists, generates
// a fresh age X25519 identity and stores it in the OS keyring (with the
// interactive passphrase prompt as the fallback on machines without a
// usable keyring).
func resolveOrCreate(cands []keyCand) (keyCand, bool, error) {
	if len(cands) > 0 {
		return cands[0], false, nil
	}
	key, err := keystore.GenerateIdentity()
	if err != nil {
		return keyCand{}, false, err
	}
	if serr := keystore.StoreKeyring(key); serr == nil {
		return keyCand{key, keystore.SourceKeyring}, true, nil
	} else if term.IsTerminal(int(os.Stdin.Fd())) {
		// Keyring unusable (headless/no GUI): fall back to the prompt,
		// which is the same path the provider uses at decrypt time.
		res, rerr := keystore.ResolveKeyMaterial(keystore.ResolveOpts{Interactive: true})
		if rerr != nil {
			return keyCand{}, false, rerr
		}
		return keyCand{res.Material, res.Source}, false, nil
	}
	return keyCand{}, false, skret.WithRemediation(
		skret.NewError(skret.ExitAuthError, "keys: could not store generated key in OS keyring", nil),
		fmt.Sprintf("set %s=<AGE-SECRET-KEY-1...>, or rerun with --passphrase-stdin < line", keystore.EnvKeyPrimary))
}

// firstOpen returns the first candidate for which opener succeeds.
func firstOpen(cands []keyCand, opener func(material string) error) (keyCand, bool) {
	for _, c := range cands {
		if err := opener(c.material); err == nil {
			return c, true
		}
	}
	return keyCand{}, false
}

// keysInitResult is the --format json payload for `keys init`. Key material
// itself is never included.
type keysInitResult struct {
	KeySource        string `json:"key_source"`
	KeyringStored    bool   `json:"keyring_stored"`
	File             string `json:"file"`
	FileEncrypted    bool   `json:"file_encrypted"`
	AlreadyEncrypted bool   `json:"already_encrypted,omitempty"`
	ConfigUpdated    bool   `json:"config_updated"`
	KDF              string `json:"kdf"`
	Format           string `json:"format,omitempty"`
}

func reportKeysInit(cmd *cobra.Command, format string, r keysInitResult) {
	if format == "json" {
		data, _ := json.MarshalIndent(r, "", "  ")
		fmt.Fprintln(cmd.OutOrStdout(), string(data))
		return
	}
	w := cmd.ErrOrStderr()
	switch {
	case r.KeyringStored:
		fmt.Fprintln(w, "Key material: generated age X25519 identity stored in OS keyring (service \"skret\")")
	case r.KeySource == keystore.SourceKeyring:
		fmt.Fprintln(w, "Key material: existing OS keyring material reused (service \"skret\")")
	case r.KDF == "scrypt":
		fmt.Fprintf(w, "Key material: %s (passphrase arm, age scrypt; not stored by skret)\n", r.KeySource)
	default:
		fmt.Fprintf(w, "Key material: %s (not stored by skret)\n", r.KeySource)
	}
	if r.AlreadyEncrypted {
		fmt.Fprintf(w, "%s already age-encrypted (verified with current key material)\n", r.File)
	} else if r.FileEncrypted {
		fmt.Fprintf(w, "Migrated %s to age-encrypted envelope (%s, atomic write, 0600)\n", r.File, r.Format)
	}
	if r.ConfigUpdated {
		fmt.Fprintln(w, "Recorded encrypted: true in .skret.yaml")
	}
}

// keysShowOpts holds `keys show` flag values.
type keysShowOpts struct {
	format string
}

func newKeysShowCmd(opts *GlobalOpts) *cobra.Command {
	so := &keysShowOpts{}
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Report encryption state of the local provider file",
		Long: `Report encryption state of the local provider file: whether the file on
disk is an encrypted envelope (standard age format or legacy
skret-encrypted-v1), the recipient/KDF recorded in its header, whether key
material is available non-interactively (and from where), plus warnings —
including high-entropy values sitting in a plaintext file. Secret values are
never printed.`,
		Example: `  skret keys show
  skret keys show --format json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return so.run(cmd, opts)
		},
	}
	cmd.Flags().StringVar(&so.format, "format", "table", "output format (table, json)")
	return cmd
}

func (o *keysShowOpts) run(cmd *cobra.Command, opts *GlobalOpts) error {
	target, err := resolveKeysTarget(opts, "")
	if err != nil {
		return err
	}
	st, err := keystore.StatusOf(target.file, target.encCfg)
	if err != nil {
		return err
	}

	if o.format == "json" {
		data, _ := json.MarshalIndent(st, "", "  ")
		fmt.Fprintln(cmd.OutOrStdout(), string(data))
		return nil
	}
	stdout := cmd.OutOrStdout()
	fmt.Fprintf(stdout, "file:       %s\n", target.file)
	fmt.Fprintf(stdout, "encrypted:  %t\n", st.Encrypted)
	if st.Encrypted {
		fmt.Fprintf(stdout, "format:     %s\n", st.Format)
		fmt.Fprintf(stdout, "kdf:        %s\n", st.KDF)
	}
	fmt.Fprintf(stdout, "config:     encrypted=%t\n", st.EncryptedCfg)
	if st.KeyAvailable {
		fmt.Fprintf(stdout, "key:        available (source: %s)\n", st.KeySource)
	} else {
		fmt.Fprintln(stdout, "key:        not available non-interactively")
	}
	for _, warning := range st.Warnings {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s\n", warning)
	}
	return nil
}

// keysTarget is the resolved context for keys commands: the local provider
// file, the config path ("" when no config is in play), the loaded config
// (nil likewise), the selected environment name, and the env's `encrypted`
// flag. Keys only apply to the local provider; anything else is a
// validation error.
type keysTarget struct {
	file    string
	cfgPath string
	cfg     *config.Config
	envName string
	encCfg  bool
}

func resolveKeysTarget(opts *GlobalOpts, fileFlag string) (*keysTarget, error) {
	path, derr := resolveConfigFile(opts)
	switch {
	case derr == nil:
		cfg, err := config.Load(path)
		if err != nil {
			return nil, skret.NewError(skret.ExitConfigError, "keys: load config failed", err)
		}
		resolved, rerr := config.Resolve(cfg, config.ResolveOpts{
			Env:      opts.Env,
			Provider: opts.Provider,
			Path:     opts.Path,
			Region:   opts.Region,
			Profile:  opts.Profile,
			File:     fileFlag,
		})
		if rerr != nil {
			return nil, skret.NewError(skret.ExitConfigError, "keys: resolve config failed", rerr)
		}
		if resolved.Provider != "local" {
			return nil, skret.NewError(skret.ExitValidationError,
				fmt.Sprintf("keys: manages the local provider, but environment %q uses %q", resolved.EnvName, resolved.Provider), nil)
		}
		file := fileFlag
		if file == "" {
			file = resolved.File
		}
		if file == "" {
			return nil, skret.NewError(skret.ExitConfigError,
				fmt.Sprintf("keys: environment %q has no local file configured", resolved.EnvName), nil)
		}
		return &keysTarget{file: file, cfgPath: path, cfg: cfg, envName: resolved.EnvName, encCfg: resolved.Encrypted}, nil
	case fileFlag != "":
		return &keysTarget{file: fileFlag}, nil
	case opts.Config != "":
		return nil, skret.NewError(skret.ExitConfigError, "keys: load config failed", derr)
	default:
		return nil, skret.NewError(skret.ExitConfigError,
			"keys: no .skret.yaml found and no --file given", nil)
	}
}

// readPassphraseStdin reads one passphrase line from stdin (scripted setup).
func readPassphraseStdin() (string, error) {
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", skret.NewError(skret.ExitAuthError, "keys: read passphrase from stdin", err)
	}
	line = trimLine(line)
	if line == "" {
		return "", skret.NewError(skret.ExitValidationError, "keys: passphrase must not be empty", nil)
	}
	return line, nil
}

// updateConfigEncryptedFlag records `encrypted: true` on the active env and
// rewrites the config atomically with a backup (the init.go convention).
func updateConfigEncryptedFlag(cfg *config.Config, cfgPath, envName string) error {
	env, ok := cfg.Environments[envName]
	if !ok {
		return skret.NewError(skret.ExitConfigError,
			fmt.Sprintf("keys: environment %q not found in config", envName), nil)
	}
	env.Encrypted = true
	cfg.Environments[envName] = env

	existing, rerr := os.ReadFile(cfgPath)
	if rerr != nil {
		return skret.NewError(skret.ExitConfigError, "keys: re-read config", rerr)
	}
	data, merr := yaml.Marshal(cfg)
	if merr != nil {
		return skret.NewError(skret.ExitGenericError, "keys: marshal config", merr)
	}
	if werr := writeConfigAtomically(cfgPath, data, existing, true); werr != nil {
		return skret.NewError(skret.ExitGenericError, "keys: write config", werr)
	}
	return nil
}

// writeFileAtomically0600 writes data to path via temp file + rename with
// 0600 permissions (the local provider's save convention).
func writeFileAtomically0600(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmpPath, err := writeTempConfig(dir, "."+filepath.Base(path)+".tmp-*", data)
	if err != nil {
		return err
	}
	defer os.Remove(tmpPath)
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}

func trimLine(s string) string {
	for s != "" && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
