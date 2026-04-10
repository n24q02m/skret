package cli

import (
	"context"
	"encoding/json"
	"sort"
	"strings"

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

	var pairs []envPair
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
	switch format {
	case "json":
		m := make(map[string]string, len(pairs))
		for _, p := range pairs {
			m[p.Name] = p.Value
		}
		data, _ := json.MarshalIndent(m, "", "  ")
		cmd.Println(string(data))

	case "yaml":
		m := make(map[string]string, len(pairs))
		for _, p := range pairs {
			m[p.Name] = p.Value
		}
		data, _ := yaml.Marshal(m)
		cmd.Print(string(data))

	case "export":
		for _, p := range pairs {
			cmd.Printf("export %s=%q\n", p.Name, p.Value)
		}

	default: // dotenv
		for _, p := range pairs {
			cmd.Printf("%s=%q\n", p.Name, escapeEnvValue(p.Value))
		}
	}
	return nil
}

func escapeEnvValue(s string) string {
	return strings.ReplaceAll(s, `"`, `\"`)
}
