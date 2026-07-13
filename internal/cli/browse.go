package cli

import (
	"context"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/n24q02m/skret/internal/provider"
	"github.com/n24q02m/skret/internal/tui"
	"github.com/n24q02m/skret/pkg/skret"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// isTerminal returns true if stdout is an interactive terminal.
// It is var-assigned to allow overriding in tests.
var isTerminal = func() bool {
	return term.IsTerminal(int(os.Stdout.Fd()))
}

// browseReveal fetches and decrypts a single secret value on demand for the TUI.
func browseReveal(p provider.SecretProvider) tui.RevealFunc {
	return func(ctx context.Context, key string) (string, error) {
		s, err := p.Get(ctx, key)
		if err != nil {
			return "", err
		}
		return s.Value, nil
	}
}

func newBrowseCmd(opts *GlobalOpts) *cobra.Command {
	return &cobra.Command{
		Use:   "browse",
		Short: "Browse secrets interactively (values are revealed on demand)",
		Long: "Opens an interactive terminal UI to browse secret key names. Listing the keys does " +
			"not decrypt anything (names only). Selecting a key decrypts and displays its value; the " +
			"revealed value is cached in memory for the rest of the session (so re-selecting it does " +
			"not re-fetch it), but is never written to disk. Requires an interactive terminal.",
		Example: "  skret browse",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !isTerminal() {
				return skret.NewError(skret.ExitValidationError, "browse requires an interactive terminal", nil)
			}
			resolved, p, err := loadProvider(opts)
			if err != nil {
				return err
			}
			defer p.Close()
			warnIfPathMangled(cmd, resolved)

			names, err := p.ListNames(context.Background(), resolved.Path)
			if err != nil {
				return skret.NewError(skret.ExitProviderError, "browse: list secrets failed", err)
			}
			if len(names) == 0 {
				cmd.PrintErrln("No secrets found to browse. Use 'skret set' to add a secret.")
				return nil
			}
			model := tui.NewModel(names, browseReveal(p))
			_, err = tea.NewProgram(model, tea.WithAltScreen()).Run()
			return err
		},
	}
}
