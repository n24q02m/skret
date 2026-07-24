package cli

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/n24q02m/skret/internal/template"
	"github.com/n24q02m/skret/pkg/skret"
	"github.com/spf13/cobra"
)

type templateOptions struct {
	opts   *GlobalOpts
	output string
}

func newTemplateCmd(opts *GlobalOpts) *cobra.Command {
	o := &templateOptions{opts: opts}
	cmd := &cobra.Command{
		Use:   "template <file>",
		Short: "Render a template file, substituting ${KEY} with secret values",
		Long: `Render a template file, substituting ${KEY} with the secret's value.

The substituted value is inserted literally and never re-scanned, so a value
containing ${OTHER} stays as-is. Write $${KEY} for a literal ${KEY}.`,
		Example: `  skret template nginx.conf.tpl
  skret template nginx.conf.tpl > nginx.conf`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.run(cmd, args[0])
		},
	}
	cmd.Flags().StringVarP(&o.output, "output", "o", "", "write to file instead of stdout")
	return cmd
}

func (o *templateOptions) run(cmd *cobra.Command, file string) error {
	content, err := os.ReadFile(file)
	if err != nil {
		return skret.NewError(skret.ExitConfigError, fmt.Sprintf("template: read %q failed", file), err)
	}

	resolved, p, err := loadProvider(o.opts)
	if err != nil {
		return err
	}
	defer p.Close()
	warnIfPathMangled(cmd, resolved)

	secrets, err := p.List(context.Background(), resolved.Path)
	if err != nil {
		return skret.NewError(skret.ExitProviderError, "template: list secrets failed", err)
	}
	if len(secrets) == 0 {
		cmd.PrintErrln("No secrets found to template. Use 'skret set' to add a secret.")
	}

	values := make(map[string]string, len(secrets))
	for _, s := range secrets {
		values[KeyToEnvName(s.Key, resolved.Path)] = s.Value
	}

	rendered, missing := template.Render(string(content), values)
	if len(missing) > 0 {
		return skret.NewError(skret.ExitValidationError,
			fmt.Sprintf("template: undefined keys: %s", strings.Join(missing, ", ")), nil)
	}

	if o.output != "" {
		if err := os.WriteFile(o.output, []byte(rendered), 0o600); err != nil {
			return skret.NewError(skret.ExitConfigError, fmt.Sprintf("template: write %q failed", o.output), err)
		}
		return nil
	}
	fmt.Fprint(cmd.OutOrStdout(), rendered)
	return nil
}
