package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/n24q02m/skret/internal/notify"
	"github.com/n24q02m/skret/internal/provider"
	"github.com/n24q02m/skret/pkg/skret"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// RotateResult is the --format json payload for one rotated key. Value is
// populated only with --show; by default the new secret never reaches
// stdout or stderr.
type RotateResult struct {
	Key       string `json:"key"`
	Path      string `json:"path,omitempty"`
	Rotated   bool   `json:"rotated"`
	Version   int64  `json:"version"`
	ExpiresAt string `json:"expires_at,omitempty"`
	Value     string `json:"value,omitempty"`
}

type rotateOptions struct {
	globals      *GlobalOpts
	genType      string
	length       int
	charset      string
	value        string
	g            bool
	ttl          string
	yes          bool
	show         bool
	strictNotify bool
	format       string
}

func newRotateCmd(opts *GlobalOpts) *cobra.Command {
	o := &rotateOptions{globals: opts}

	cmd := &cobra.Command{
		Use:   "rotate <KEY> [KEY...]",
		Short: "Replace a secret's value with a fresh generated value",
		Long: `Rotate one or more secrets: store a new value and record the change.

By default the new value is drawn from the generate engine (crypto/rand,
rejection sampling — see ` + "`skret generate`" + `); --type/--length/--charset tune it,
and --value stores an explicit value instead. Expiry metadata can be
recorded with --ttl (e.g. 720h or 30d): stored as the "skret-expires-at"
resource tag on AWS and as file metadata on the local provider, where
` + "`skret list --values`" + ` surfaces it (near-expiry keys warn on stderr).

Non-interactive by design: a confirmation prompt appears only on an
interactive terminal — CI and piped invocations rotate without asking;
pass --yes to skip the prompt there too. The new value is never printed:
stdout carries nothing (table) or the JSON envelope (--format json);
--show additionally prints the value on stdout, one line per key. Every
rotation is a new provider version, visible via ` + "`skret history KEY`" + `
where the provider tracks versions (e.g. AWS).`,
		Example: `  skret rotate API_KEY
  skret rotate API_KEY --type hex --length 64
  skret rotate API_KEY --value ghp_replacedmanually --ttl 720h
  skret rotate API_KEY DB_PASS --yes --format json
  skret rotate API_KEY --show`,
		Args:              cobra.MinimumNArgs(1),
		ValidArgsFunction: secretKeyCompletion(opts),
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.run(cmd, args)
		},
	}

	cmd.Flags().BoolVar(&o.g, "generate", true, "generate the new value with the generate engine (default)")
	cmd.Flags().StringVar(&o.value, "value", "", "store this explicit value instead of generating")
	cmd.Flags().StringVar(&o.genType, "type", "password", "generated value type (password, uuid, hex, base64)")
	cmd.Flags().IntVar(&o.length, "length", 32, "generated length in characters (1-1048576; uuid is fixed at 36)")
	cmd.Flags().StringVar(&o.charset, "charset", "alnum", "generated password charset (alnum, alnum+symbols, symbols)")
	cmd.Flags().StringVar(&o.ttl, "ttl", "", "record expiry metadata (e.g. 720h, 12h30m, 30d)")
	cmd.Flags().BoolVar(&o.yes, "yes", false, "skip the confirmation prompt")
	cmd.Flags().BoolVar(&o.show, "show", false, "print the new value on stdout (default: never print values)")
	cmd.Flags().BoolVar(&o.strictNotify, "strict-notify", false, "fail the command if the mutation webhook fails (default: warn only)")
	cmd.Flags().StringVar(&o.format, "format", "table", "output format (table, json)")

	return cmd
}

func (o *rotateOptions) run(cmd *cobra.Command, args []string) error {
	// Validate everything before touching the provider so an invalid
	// invocation never rotates a subset of the keys.
	var expiry time.Time
	if o.ttl != "" {
		d, err := parseTTL(o.ttl)
		if err != nil {
			return skret.NewError(skret.ExitValidationError, "rotate: --ttl "+err.Error(), nil)
		}
		expiry = time.Now().Add(d)
	}

	explicit := o.value != ""
	if explicit && o.g && cmd.Flags().Changed("generate") {
		return skret.NewError(skret.ExitValidationError,
			"rotate: --value and --generate are mutually exclusive", nil)
	}
	if explicit && (cmd.Flags().Changed("type") || cmd.Flags().Changed("length") || cmd.Flags().Changed("charset")) {
		return skret.NewError(skret.ExitValidationError,
			"rotate: --type/--length/--charset only apply when generating (drop --value or the flags)", nil)
	}
	if !explicit && !o.g {
		return skret.NewError(skret.ExitValidationError,
			"rotate: --generate=false requires --value", nil)
	}
	if !explicit {
		if err := validateGenValueFlags(cmd, "rotate", o.genType, o.charset, o.length); err != nil {
			return err
		}
	}
	if o.format != "table" && o.format != "json" {
		return skret.NewError(skret.ExitValidationError,
			fmt.Sprintf("rotate: unknown --format %q (table, json)", o.format), nil)
	}

	resolved, p, err := loadProvider(o.globals)
	if err != nil {
		return err
	}
	defer p.Close()
	warnIfPathMangled(cmd, resolved)

	ctx := context.Background()

	// Preflight every key before mutating any, so a typo cannot leave a
	// half-rotated batch behind.
	keys := make([]string, 0, len(args))
	metas := make([]provider.SecretMeta, 0, len(args))
	for _, arg := range args {
		key, mangled := resolveKeyArg(resolved.Path, arg)
		if mangled {
			cmd.PrintErrf("warning: key looked shell-mangled; using %q (omit the leading slash, or set MSYS_NO_PATHCONV=1)\n", key)
		}
		current, getErr := p.Get(ctx, key)
		if getErr != nil {
			if errors.Is(getErr, provider.ErrNotFound) {
				return skret.NewError(skret.ExitNotFoundError,
					fmt.Sprintf("Nothing to rotate: %q not found. Use 'skret set' to create it first.", key), getErr)
			}
			return skret.NewError(skret.ExitProviderError, fmt.Sprintf("rotate %q: read current value", key), getErr)
		}
		keys = append(keys, key)
		metas = append(metas, current.Meta)
	}

	// Confirmation only on an interactive terminal: CI and pipes rotate
	// without asking (that is the point of `rotate KEY` in automation).
	if !o.yes && term.IsTerminal(int(os.Stdin.Fd())) {
		cmd.PrintErrf("Rotate %d secret(s)? [y/N] ", len(keys))
		answer, _ := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
		if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(answer)), "y") {
			cmd.PrintErrln("Cancelled.")
			return nil
		}
	}

	results := make([]RotateResult, 0, len(keys))
	for i, key := range keys {
		var newValue string
		if explicit {
			newValue = o.value
		} else {
			generated, _, genErr := generateValue(o.genType, o.length, o.charset)
			if genErr != nil {
				return skret.NewError(skret.ExitGenericError, "rotate: crypto/rand failed", genErr)
			}
			newValue = generated
		}

		meta := metas[i] // preserve description/tags and any recorded expiry
		if !expiry.IsZero() {
			meta.ExpiresAt = expiry
		}
		if err := p.Set(ctx, key, newValue, meta); err != nil {
			return wrapProviderMutationError("rotate", key, err)
		}

		// The rotation is durable; the webhook reports it (names only). A
		// notify failure never rolls the write back -- warn, or fail
		// post-hoc under --strict-notify.
		if err := reportMutation(cmd, resolved, o.strictNotify, notify.EventRotate, key); err != nil {
			return err
		}

		res := RotateResult{Key: key, Path: resolved.Path, Rotated: true}
		if s, err := p.Get(ctx, key); err == nil {
			res.Version = s.Version
			if !s.Meta.ExpiresAt.IsZero() {
				res.ExpiresAt = s.Meta.ExpiresAt.UTC().Format(time.RFC3339)
			}
		}
		if o.show {
			res.Value = newValue
		}
		results = append(results, res)

		if o.format != "json" {
			cmd.PrintErrf("Rotated %s\n", key)
		}
	}

	stdout := cmd.OutOrStdout()
	if o.format == "json" {
		var payload any = results[0]
		if len(results) > 1 {
			payload = results
		}
		data, mErr := json.MarshalIndent(payload, "", "  ")
		if mErr != nil {
			return skret.NewError(skret.ExitGenericError, "rotate: encode result", mErr)
		}
		fmt.Fprintln(stdout, string(data))
		return nil
	}

	// Table + --show: values go to stdout one per line, in argument order,
	// after all mutations have succeeded.
	if o.show {
		for _, res := range results {
			fmt.Fprintln(stdout, res.Value)
		}
	}
	return nil
}
