package cli

import (
	"context"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/n24q02m/skret/internal/tui"
	"github.com/n24q02m/skret/pkg/skret"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func newBrowseCmd(opts *GlobalOpts) *cobra.Command {
	return &cobra.Command{
		Use:   "browse",
		Short: "Browse secrets interactively (values are revealed on demand)",
		RunE: func(_ *cobra.Command, _ []string) error {
			if !term.IsTerminal(int(os.Stdout.Fd())) {
				return skret.NewError(skret.ExitValidationError, "browse requires an interactive terminal", nil)
			}
			resolved, p, err := loadProvider(opts)
			if err != nil {
				return err
			}
			defer p.Close()

			names, err := p.ListNames(context.Background(), resolved.Path)
			if err != nil {
				return skret.NewError(skret.ExitProviderError, "browse: list secrets failed", err)
			}
			reveal := func(ctx context.Context, key string) (string, error) {
				s, err := p.Get(ctx, key)
				if err != nil {
					return "", err
				}
				return s.Value, nil
			}
			model := tui.NewModel(names, reveal)
			_, err = tea.NewProgram(model, tea.WithAltScreen()).Run()
			return err
		},
	}
}
