package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/n24q02m/skret/internal/dotenv"
	skexec "github.com/n24q02m/skret/internal/exec"
	"github.com/n24q02m/skret/pkg/skret"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

type envPair struct {
	Name  string
	Value string
}

func newEnvCmd(opts *GlobalOpts) *cobra.Command {
	var format string

	cmd := &cobra.Command{
		Use:   "env",
		Short: "Dump all secrets in dotenv/JSON/YAML/export format",
		RunE: func(cmd *cobra.Command, _ []string) error {
			pairs, err := getEnvPairs(opts)
			if err != nil {
				return err
			}
			return printEnvPairs(cmd, pairs, format)
		},
	}

	cmd.Flags().StringVar(&format, "format", "dotenv", "output format (dotenv, json, yaml, export)")

	return cmd
}

func getEnvPairs(opts *GlobalOpts) ([]envPair, error) {
	resolved, p, err := loadProvider(opts)
	if err != nil {
		return nil, err
	}
	defer p.Close()

	ctx := context.Background()
	secrets, err := p.List(ctx, resolved.Path)
	if err != nil {
		return nil, skret.NewError(skret.ExitProviderError, "env: list secrets failed", err)
	}

	if err := skexec.DetectEnvNameCollisions(secrets, resolved.Path, resolved.Exclude); err != nil {
		return nil, skret.NewError(skret.ExitConfigError, "env: "+err.Error(), nil)
	}

	pairs := make([]envPair, 0, len(secrets))
	excludeSet := make(map[string]bool, len(resolved.Exclude))
	for _, e := range resolved.Exclude {
		excludeSet[e] = true
	}
	for _, s := range secrets {
		name := KeyToEnvName(s.Key, resolved.Path)
		if excludeSet[name] {
			continue
		}
		pairs = append(pairs, envPair{Name: name, Value: s.Value})
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].Name < pairs[j].Name })

	return pairs, nil
}

func printEnvPairs(cmd *cobra.Command, pairs []envPair, format string) error {
	if len(pairs) == 0 {
		cmd.PrintErrln("No secrets found. Use 'skret set' to add a secret.")
		if format != "json" && format != "yaml" {
			return nil
		}
	}

	out := cmd.OutOrStdout()
	switch format {
	case "json":
		m := make(map[string]string, len(pairs))
		for _, p := range pairs {
			m[p.Name] = p.Value
		}
		data, err := json.MarshalIndent(m, "", "  ")
		if err != nil {
			return skret.NewError(skret.ExitGenericError, "env: json marshal failed", err)
		}
		fmt.Fprintln(out, string(data))

	case "yaml":
		m := make(map[string]string, len(pairs))
		for _, p := range pairs {
			m[p.Name] = p.Value
		}
		data, err := yaml.Marshal(m)
		if err != nil {
			return skret.NewError(skret.ExitGenericError, "env: yaml marshal failed", err)
		}
		fmt.Fprint(out, string(data))

	case "export":
		for _, p := range pairs {
			fmt.Fprintf(out, "export %s=%s\n", p.Name, shellSingleQuote(p.Value))
		}

	default: // dotenv
		for _, p := range pairs {
			fmt.Fprintln(out, dotenv.Encode(p.Name, p.Value))
		}
	}
	return nil
}

// shellSingleQuote wraps a value in POSIX single quotes so a shell that evaluates
// `export NAME=<this>` reproduces the exact bytes — no parameter expansion, no
// command substitution. An embedded single quote is emitted as '\” .
func shellSingleQuote(s string) string {
	// OPTIMIZATION: skip strings.ReplaceAll overhead if no single quote is present
	if strings.IndexByte(s, '\'') == -1 {
		return "'" + s + "'"
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
