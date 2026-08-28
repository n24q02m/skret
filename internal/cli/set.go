package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/n24q02m/skret/internal/provider"
	"github.com/n24q02m/skret/pkg/skret"
	"github.com/spf13/cobra"
)

type setOptions struct {
	globals     *GlobalOpts
	fromStdin   bool
	fromFile    string
	description string
	tags        []string
	format      string
}

// SetResult is the --format json payload for a successful `set`.
type SetResult struct {
	Key     string `json:"key"`
	Path    string `json:"path"`
	Version int64  `json:"version"`
	Created bool   `json:"created"`
}

func newSetCmd(opts *GlobalOpts) *cobra.Command {
	o := &setOptions{globals: opts}

	cmd := &cobra.Command{
		Use:   "set <KEY> [VALUE]",
		Short: "Create or update a secret",
		Long: `Create or update a secret's value.

Provide the value as an argument, piped via --from-stdin, or from a file with
--from-file. For a value that begins with '-' (a PEM key, a flag-like token),
put '--' before the key so it is not parsed as a flag. --from-stdin and
--from-file strip trailing newlines; use them for multi-line values.`,
		Example: `  skret set API_KEY ghp_xxx
  skret set -- PRIVATE_KEY "-----BEGIN KEY-----..."
  cat key.pem | skret set TLS_KEY --from-stdin
  skret set TLS_KEY --from-file key.pem`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.run(cmd, args)
		},
	}

	cmd.Flags().BoolVarP(&o.fromStdin, "from-stdin", "s", false, "read value from stdin")
	cmd.Flags().StringVarP(&o.fromFile, "from-file", "f", "", "read value from file")
	cmd.Flags().StringVarP(&o.description, "description", "d", "", "secret description")
	cmd.Flags().StringArrayVarP(&o.tags, "tag", "t", nil, "secret tag (key=value, repeatable)")
	cmd.Flags().StringVar(&o.format, "format", "table", "output format (table, json)")

	return cmd
}

func (o *setOptions) run(cmd *cobra.Command, args []string) error {
	resolved, p, err := loadProvider(o.globals)
	if err != nil {
		return err
	}
	defer p.Close()
	warnIfPathMangled(cmd, resolved)

	key, mangled := resolveKeyArg(resolved.Path, args[0])
	if mangled {
		cmd.PrintErrf("warning: key looked shell-mangled; using %q (omit the leading slash, or set MSYS_NO_PATHCONV=1)\n", key)
	}
	value, err := o.getValue(args)
	if err != nil {
		return err
	}

	meta := o.getMeta()

	ctx := context.Background()

	// The existence check only runs for --format json, where a scripting
	// agent needs to know whether the write created a new secret or
	// overwrote one; the table path takes no extra provider round trip and
	// its output stays exactly as before.
	var created bool
	if o.format == "json" {
		_, getErr := p.Get(ctx, key)
		created = errors.Is(getErr, provider.ErrNotFound)
	}

	if err := p.Set(ctx, key, value, meta); err != nil {
		return wrapProviderMutationError("set", key, err)
	}

	if o.format == "json" {
		return o.printResult(cmd, key, resolved.Path, created, p)
	}

	cmd.PrintErrf("Set %s\n", key)
	return nil
}

// printResult renders the --format json payload for a successful set. It
// re-reads the secret to report the version the provider assigned to this
// write (0 for a provider, like local, that does not track versions); the
// value itself is never included.
func (o *setOptions) printResult(cmd *cobra.Command, key, path string, created bool, p provider.SecretProvider) error {
	var version int64
	if s, err := p.Get(context.Background(), key); err == nil {
		version = s.Version
	}

	data, err := json.MarshalIndent(SetResult{
		Key: key, Path: path, Version: version, Created: created,
	}, "", "  ")
	if err != nil {
		return skret.NewError(skret.ExitGenericError, "set: encode result", err)
	}
	fmt.Fprintln(cmd.OutOrStdout(), string(data))
	return nil
}

func (o *setOptions) getValue(args []string) (string, error) {
	switch {
	case len(args) == 2:
		return args[1], nil
	case o.fromStdin:
		// Read the entire stream (not line-by-line: bufio.Scanner.Scan()
		// only returns the first line, silently truncating any multi-line
		// value such as a PEM key). Strip trailing "\n" bytes to match
		// --from-file's convention below and POSIX `$(...)` command
		// substitution ergonomics -- see docs/guide/value-fidelity.md.
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return "", skret.NewError(skret.ExitGenericError, "set: read stdin failed", err)
		}
		return strings.TrimRight(string(data), "\n"), nil
	case o.fromFile != "":
		data, err := os.ReadFile(o.fromFile)
		if err != nil {
			return "", skret.NewError(skret.ExitGenericError, fmt.Sprintf("set: read file %q", o.fromFile), err)
		}
		return strings.TrimRight(string(data), "\n"), nil
	default:
		return "", skret.NewError(skret.ExitValidationError, "set: value required (provide as argument, --from-stdin, or --from-file)", nil)
	}
}

func (o *setOptions) getMeta() provider.SecretMeta {
	meta := provider.SecretMeta{Description: o.description}
	if len(o.tags) > 0 {
		meta.Tags = make(map[string]string, len(o.tags))
		for _, tag := range o.tags {
			key, val, found := strings.Cut(tag, "=")
			if found {
				meta.Tags[key] = val
			}
		}
	}
	return meta
}
