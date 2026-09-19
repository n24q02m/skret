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
  1. SKRET_AGE_KEY / SKRET_LOCAL_KEY already set — validated, nothing stored.
  2. OS keyring — a fresh 256-bit key is generated and stored
     (service "skret", user "local-enc-key") and verified round-trip.
  3. --passphrase-stdin — one passphrase line is read from stdin
     (scripted setups on machines without an OS keyring).
  4. Interactive passphrase prompt (confirm twice) — only when stdin is a
     terminal; never in non-interactive mode (exit 4 with a remediation hint).

The key material is never printed. With --encrypt-existing the local file is
converted to an encrypted envelope in place (atomic write, 0600) and
` + "`encrypted: true`" + ` is recorded for the active environment in .skret.yaml.`,
		Example: `  skret keys init
  skret keys init --encrypt-existing
  skret keys init --file=./.secrets.dev.yaml --encrypt-existing --format json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return ko.run(cmd, opts)
		},
	}
	cmd.Flags().StringVar(&ko.file, "file", "", "local provider file (default: file of the active environment in .skret.yaml)")
	cmd.Flags().BoolVar(&ko.encryptExisting, "encrypt-existing", false, "migrate the plaintext local file to an encrypted envelope in place")
	cmd.Flags().BoolVar(&ko.passphraseStdin, "passphrase-stdin", false, "read the passphrase from stdin (one line) instead of generating/storing a key")
	cmd.Flags().StringVar(&ko.format, "format", "table", "output format (table, json)")
	return cmd
}

func (o *keysInitOpts) run(cmd *cobra.Command, opts *GlobalOpts) error {
	file, cfgPath, cfg, envName, encCfg, err := resolveKeysTarget(opts, o.file)
	if err != nil {
		return err
	}

	// 1. Env vars win, matching the runtime resolution order.
	material, source := envKeyMaterial()
	keyringStored := false
	if material == "" && o.passphraseStdin {
		pw, perr := readPassphraseStdin()
		if perr != nil {
			return perr
		}
		material, source = pw, keystore.SourcePassphr
	}
	if material == "" {
		key, gerr := keystore.GenerateKey()
		if gerr != nil {
			return gerr
		}
		if serr := keystore.StoreKeyring(key); serr == nil {
			material, source, keyringStored = key, keystore.SourceKeyring, true
		} else if term.IsTerminal(int(os.Stdin.Fd())) {
			// Keyring unusable (headless/no GUI): fall back to the prompt,
			// which is the same path the provider uses at decrypt time.
			res, rerr := keystore.ResolveKeyMaterial(keystore.ResolveOpts{Interactive: true})
			if rerr != nil {
				return rerr
			}
			material, source = res.Material, res.Source
		} else {
			return skret.WithRemediation(
				skret.NewError(skret.ExitAuthError, "keys: could not store generated key in OS keyring", nil),
				fmt.Sprintf("set %s=<key-material>, or rerun with --passphrase-stdin < line", keystore.EnvKeyPrimary))
		}
	}

	result := keysInitResult{
		KeySource:        source,
		KeyringStored:    keyringStored,
		File:             file,
		FileEncrypted:    false,
		KDF:              "argon2id",
		ConfigUpdated:    false,
		AlreadyEncrypted: false,
	}

	if o.encryptExisting {
		raw, rerr := os.ReadFile(file)
		switch {
		case rerr == nil:
			if keystore.Detect(raw) {
				// Verify the current key material still decrypts it.
				if _, derr := keystore.Open(raw, material); derr != nil {
					return derr
				}
				result.FileEncrypted = true
				result.AlreadyEncrypted = true
			} else {
				var secrets map[string]string
				if uerr := yaml.Unmarshal(raw, &struct {
					Secrets *map[string]string `yaml:"secrets"`
				}{&secrets}); uerr != nil {
					return skret.NewError(skret.ExitConfigError,
						fmt.Sprintf("keys: parse plaintext file %q", file), uerr)
				}
				sealed, serr := keystore.Seal(secrets, material, nil)
				if serr != nil {
					return serr
				}
				if werr := writeFileAtomically0600(file, sealed); werr != nil {
					return skret.NewError(skret.ExitGenericError,
						fmt.Sprintf("keys: write encrypted %q", file), werr)
				}
				result.FileEncrypted = true
			}
		case errors.Is(rerr, os.ErrNotExist):
			// Nothing to migrate yet: first write under the flipped config
			// flag will produce an envelope.
		default:
			return skret.NewError(skret.ExitConfigError,
				fmt.Sprintf("keys: read %q", file), rerr)
		}

		if cfg != nil && !encCfg {
			if uerr := updateConfigEncryptedFlag(cfg, cfgPath, envName); uerr != nil {
				return uerr
			}
			result.ConfigUpdated = true
		}
	}

	reportKeysInit(cmd, o.format, result)
	return nil
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
}

func reportKeysInit(cmd *cobra.Command, format string, r keysInitResult) {
	if format == "json" {
		data, _ := json.MarshalIndent(r, "", "  ")
		fmt.Fprintln(cmd.OutOrStdout(), string(data))
		return
	}
	w := cmd.ErrOrStderr()
	switch r.KeySource {
	case keystore.SourceKeyring:
		fmt.Fprintln(w, "Key material: generated 256-bit key stored in OS keyring (service \"skret\")")
	default:
		fmt.Fprintf(w, "Key material: %s (not stored by skret)\n", r.KeySource)
	}
	if r.AlreadyEncrypted {
		fmt.Fprintf(w, "%s already encrypted (verified with current key)\n", r.File)
	} else if r.FileEncrypted {
		fmt.Fprintf(w, "Migrated %s to encrypted envelope (%s, atomic write, 0600)\n", r.File, r.KDF)
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
disk is an encrypted envelope, the KDF recorded in its header, whether key
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
	file, _, _, _, encCfg, err := resolveKeysTarget(opts, "")
	if err != nil {
		return err
	}
	st, err := keystore.StatusOf(file, encCfg)
	if err != nil {
		return err
	}

	if o.format == "json" {
		data, _ := json.MarshalIndent(st, "", "  ")
		fmt.Fprintln(cmd.OutOrStdout(), string(data))
		return nil
	}
	stdout := cmd.OutOrStdout()
	fmt.Fprintf(stdout, "file:       %s\n", file)
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

// resolveKeysTarget locates the local provider file for keys commands:
// explicit --file > the active environment's file in .skret.yaml. It returns
// the file path, the config path ("" when no config is in play), the loaded
// config (nil likewise), the selected environment name, and the env's
// `encrypted` flag. Keys only apply to the local provider; anything else is
// a validation error.
func resolveKeysTarget(opts *GlobalOpts, fileFlag string) (file, cfgPath string, cfg *config.Config, envName string, encCfg bool, err error) {
	path, derr := resolveConfigFile(opts)
	switch {
	case derr == nil:
		cfg, err = config.Load(path)
		if err != nil {
			return "", "", nil, "", false, skret.NewError(skret.ExitConfigError, "keys: load config failed", err)
		}
		cfgPath = path
		resolved, rerr := config.Resolve(cfg, config.ResolveOpts{
			Env:      opts.Env,
			Provider: opts.Provider,
			Path:     opts.Path,
			Region:   opts.Region,
			Profile:  opts.Profile,
			File:     fileFlag,
		})
		if rerr != nil {
			return "", "", nil, "", false, skret.NewError(skret.ExitConfigError, "keys: resolve config failed", rerr)
		}
		if resolved.Provider != "local" {
			return "", "", nil, "", false, skret.NewError(skret.ExitValidationError,
				fmt.Sprintf("keys: manages the local provider, but environment %q uses %q", resolved.EnvName, resolved.Provider), nil)
		}
		file = fileFlag
		if file == "" {
			file = resolved.File
		}
		if file == "" {
			return "", "", nil, "", false, skret.NewError(skret.ExitConfigError,
				fmt.Sprintf("keys: environment %q has no local file configured", resolved.EnvName), nil)
		}
		return file, cfgPath, cfg, resolved.EnvName, resolved.Encrypted, nil
	case fileFlag != "":
		return fileFlag, "", nil, "", false, nil
	case opts.Config != "":
		return "", "", nil, "", false, skret.NewError(skret.ExitConfigError, "keys: load config failed", derr)
	default:
		return "", "", nil, "", false, skret.NewError(skret.ExitConfigError,
			"keys: no .skret.yaml found and no --file given", nil)
	}
}

// envKeyMaterial consults SKRET_AGE_KEY then SKRET_LOCAL_KEY, mirroring the
// runtime resolution order. Returns ("", "") when neither is set.
func envKeyMaterial() (material, source string) {
	for _, name := range []string{keystore.EnvKeyPrimary, keystore.EnvKeyFallback} {
		if v := os.Getenv(name); v != "" {
			return v, keystore.SourceEnv + ":" + name
		}
	}
	return "", ""
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
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
