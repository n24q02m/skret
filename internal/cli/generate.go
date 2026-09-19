package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	"github.com/n24q02m/skret/internal/provider"
	"github.com/n24q02m/skret/pkg/skret"
	"github.com/spf13/cobra"
)

const (
	generateAlnum       = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	generateSymbols     = "!@#$%^&*()-_=+[]{};:,."
	generateHex         = "0123456789abcdef"
	generateBase64      = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	generateMaxLen      = 1 << 20 // 1 MiB cap so a typo cannot allocate unbounded output
	generateMaxCount    = 10000
	generateUUIDLength  = 36 // 8-4-4-4-12 hex with dashes (RFC 4122 v4)
	generateReadChunkSz = 512
)

// genRandReader is the randomness source; a variable so tests can inject a
// deterministic reader (same pattern as internal/auth/rand.go).
var genRandReader io.Reader = rand.Reader

type generateOptions struct {
	globals *GlobalOpts
	genType string
	length  int
	charset string
	count   int
	setKey  string
	plain   bool
	format  string
}

// GenerateResult is one element of the --format json payload. Key is set
// only when --set stored the value via a provider.
type GenerateResult struct {
	Value  string `json:"value"`
	Type   string `json:"type"`
	Length int    `json:"length"`
	Key    string `json:"key,omitempty"`
}

func newGenerateCmd(opts *GlobalOpts) *cobra.Command {
	o := &generateOptions{globals: opts}

	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate a random password, UUID, hex, or base64 value",
		Long: `Generate a random value with crypto/rand (never math/rand).

Works offline: no provider or .skret.yaml is needed unless --set is used.
stdout carries only the generated value(s) — one per line, or exact raw
bytes with --plain — so the output can be piped or captured verbatim.
Invalid flags or values exit 8 (ExitValidationError).

Alphabet mapping uses rejection sampling, so every character of the chosen
charset is equally likely (no modulo bias).`,
		Example: `  skret generate --type password --length 32
  skret generate --type hex --length 16 --count 5
  skret generate --type password --charset alnum+symbols --format json
  skret generate --type password --set API_KEY`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.run(cmd)
		},
	}

	cmd.Flags().StringVar(&o.genType, "type", "password", "value type (password, uuid, hex, base64)")
	cmd.Flags().IntVar(&o.length, "length", 32, "output length in characters (1-1048576; uuid is fixed at 36)")
	cmd.Flags().StringVar(&o.charset, "charset", "alnum", "password charset (alnum, alnum+symbols, symbols)")
	cmd.Flags().IntVar(&o.count, "count", 1, "number of values to generate (1-10000)")
	cmd.Flags().StringVar(&o.setKey, "set", "", "also store the value as secret KEY via the configured provider")
	cmd.Flags().BoolVar(&o.plain, "plain", false, "print exact value bytes with no trailing newline (count must be 1)")
	cmd.Flags().StringVar(&o.format, "format", "table", "output format (table, json)")

	return cmd
}

func (o *generateOptions) run(cmd *cobra.Command) error {
	results, err := o.validateAndGenerate(cmd)
	if err != nil {
		return err
	}

	if o.setKey != "" {
		_, p, err := loadProvider(o.globals)
		if err != nil {
			return err
		}
		defer p.Close()
		if err := p.Set(context.Background(), o.setKey, results[0].Value, provider.SecretMeta{}); err != nil {
			return wrapProviderMutationError("set", o.setKey, err)
		}
		for i := range results {
			results[i].Key = o.setKey
		}
		cmd.PrintErrf("Set %s\n", o.setKey)
	}

	stdout := cmd.OutOrStdout()
	if o.format == "json" {
		var payload any
		if len(results) == 1 {
			payload = results[0]
		} else {
			payload = results
		}
		data, mErr := json.MarshalIndent(payload, "", "  ")
		if mErr != nil {
			return skret.NewError(skret.ExitGenericError, "generate: json marshal failed", mErr)
		}
		fmt.Fprintln(stdout, string(data))
		return nil
	}

	// Table: value(s) only on stdout. One per line, or raw bytes with no
	// trailing newline for --plain (mirrors skret get --plain; --plain is
	// rejected for --count > 1).
	for _, r := range results {
		if o.plain {
			fmt.Fprint(stdout, r.Value)
		} else {
			fmt.Fprintln(stdout, r.Value)
		}
	}
	return nil
}

// validateAndGenerate checks every flag before generating anything, so an
// invalid invocation never emits partial output.
func (o *generateOptions) validateAndGenerate(cmd *cobra.Command) ([]GenerateResult, error) {
	switch o.genType {
	case "password", "uuid", "hex", "base64":
	default:
		return nil, skret.NewError(skret.ExitValidationError,
			fmt.Sprintf("generate: unknown --type %q (password, uuid, hex, base64)", o.genType), nil)
	}

	if o.genType == "uuid" {
		if cmd.Flags().Changed("length") {
			return nil, skret.NewError(skret.ExitValidationError,
				"generate: --length does not apply to uuid (fixed 36 characters)", nil)
		}
		if cmd.Flags().Changed("charset") {
			return nil, skret.NewError(skret.ExitValidationError,
				"generate: --charset does not apply to uuid", nil)
		}
	} else if o.length < 1 || o.length > generateMaxLen {
		return nil, skret.NewError(skret.ExitValidationError,
			fmt.Sprintf("generate: --length must be between 1 and %d (got %d)", generateMaxLen, o.length), nil)
	}

	if o.genType == "password" {
		switch o.charset {
		case "alnum", "alnum+symbols", "symbols":
		default:
			return nil, skret.NewError(skret.ExitValidationError,
				fmt.Sprintf("generate: unknown --charset %q (alnum, alnum+symbols, symbols)", o.charset), nil)
		}
	}

	if o.genType != "password" && cmd.Flags().Changed("charset") {
		return nil, skret.NewError(skret.ExitValidationError,
			fmt.Sprintf("generate: --charset only applies to --type password (got --type %s)", o.genType), nil)
	}

	if o.count < 1 || o.count > generateMaxCount {
		return nil, skret.NewError(skret.ExitValidationError,
			fmt.Sprintf("generate: --count must be between 1 and %d (got %d)", generateMaxCount, o.count), nil)
	}
	if o.setKey != "" && o.count > 1 {
		return nil, skret.NewError(skret.ExitValidationError,
			"generate: --set stores a single value; drop --count or --set", nil)
	}
	if o.plain && o.count > 1 {
		return nil, skret.NewError(skret.ExitValidationError,
			"generate: --plain emits exact bytes with no separator; it requires --count 1", nil)
	}
	if o.format != "table" && o.format != "json" {
		return nil, skret.NewError(skret.ExitValidationError,
			fmt.Sprintf("generate: unknown --format %q (table, json)", o.format), nil)
	}

	results := make([]GenerateResult, 0, o.count)
	for range o.count {
		value, length, gErr := o.generateOne()
		if gErr != nil {
			return nil, skret.NewError(skret.ExitGenericError, "generate: crypto/rand failed", gErr)
		}
		results = append(results, GenerateResult{Value: value, Type: o.genType, Length: length})
	}
	return results, nil
}

// generateOne returns the value and its effective output length (uuid is
// fixed at 36 regardless of --length).
func (o *generateOptions) generateOne() (string, int, error) {
	switch o.genType {
	case "uuid":
		value, err := uuidV4(genRandReader)
		return value, generateUUIDLength, err
	case "hex":
		value, err := randomFromAlphabet(o.length, generateHex, genRandReader)
		return value, o.length, err
	case "base64":
		value, err := randomFromAlphabet(o.length, generateBase64, genRandReader)
		return value, o.length, err
	default: // password
		alphabet := generateAlnum
		switch o.charset {
		case "alnum+symbols":
			alphabet = generateAlnum + generateSymbols
		case "symbols":
			alphabet = generateSymbols
		}
		value, err := randomFromAlphabet(o.length, alphabet, genRandReader)
		return value, o.length, err
	}
}

// randomFromAlphabet draws one uniformly distributed symbol per output
// position using rejection sampling: bytes at or above the largest multiple
// of len(alphabet) are discarded instead of wrapped, so the mapping stays
// unbiased (naive b%k over-weights the first 256%k symbols). The limit is
// kept as an int: when k divides 256 the limit is 256, which no byte
// reaches — as a byte it would wrap to 0 and reject everything.
func randomFromAlphabet(n int, alphabet string, rnd io.Reader) (string, error) {
	k := len(alphabet)
	lim := 256 - (256 % k)
	out := make([]byte, 0, n)
	buf := make([]byte, generateReadChunkSz)
	for len(out) < n {
		if _, err := io.ReadFull(rnd, buf); err != nil {
			return "", err
		}
		for _, b := range buf {
			if int(b) >= lim {
				continue
			}
			out = append(out, alphabet[int(b)%k])
			if len(out) == n {
				break
			}
		}
	}
	return string(out), nil
}

// uuidV4 renders an RFC 4122 version-4 UUID: 16 random bytes with the
// version (4) and variant (10xx) bits set, formatted 8-4-4-4-12.
func uuidV4(rnd io.Reader) (string, error) {
	var b [16]byte
	if _, err := io.ReadFull(rnd, b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80

	dst := make([]byte, generateUUIDLength)
	hex.Encode(dst[0:8], b[0:4])
	dst[8] = '-'
	hex.Encode(dst[9:13], b[4:6])
	dst[13] = '-'
	hex.Encode(dst[14:18], b[6:8])
	dst[18] = '-'
	hex.Encode(dst[19:23], b[8:10])
	dst[23] = '-'
	hex.Encode(dst[24:36], b[10:16])
	return string(dst), nil
}
