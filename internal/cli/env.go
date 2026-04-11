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

func newEnvCmd(opts *GlobalOpts) *cobra.Command {
	var format string

	cmd := &cobra.Command{
		Use:   "env",
		Short: "Dump all secrets in dotenv/JSON/YAML/export format",
		RunE: func(cmd *cobra.Command, _ []string) error {
			resolved, p, err := loadProvider(opts)
			if err != nil {
				return err
			}
			defer func() { _ = p.Close() }()

			ctx := context.Background()
			secrets, err := p.List(ctx, resolved.Path)
			if err != nil {
				return skret.NewError(skret.ExitProviderError, "env: list secrets failed", err)
			}

			type kv struct {
				Name  string
				Value string
			}
			var pairs []kv
			excludeSet := make(map[string]bool, len(resolved.Exclude))
			for _, e := range resolved.Exclude {
				excludeSet[e] = true
			}
			for _, s := range secrets {
				name := KeyToEnvName(s.Key, resolved.Path)
				if excludeSet[name] {
					continue
				}
				pairs = append(pairs, kv{Name: name, Value: s.Value})
			}
			sort.Slice(pairs, func(i, j int) bool { return pairs[i].Name < pairs[j].Name })

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
		},
	}

	cmd.Flags().StringVar(&format, "format", "dotenv", "output format (dotenv, json, yaml, export)")

	return cmd
}

func escapeEnvValue(s string) string {
	return strings.ReplaceAll(s, `"`, `\"`)
}
