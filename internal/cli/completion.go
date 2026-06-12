package cli

import (
	"context"
	"strings"

	"github.com/spf13/cobra"
)

// namesProvider returns secret key names plus the resolved path prefix.
type namesProvider func() (names []string, pathPrefix string, err error)

// completionFromNames builds a cobra completion func over a names source. It is
// best-effort: any error yields no candidates (never an error to the shell).
func completionFromNames(src namesProvider) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(_ *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if len(args) > 0 {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		names, prefix, err := src()
		if err != nil {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		return filterByPrefix(stripCompletionPrefix(names, prefix), toComplete), cobra.ShellCompDirectiveNoFileComp
	}
}

// secretKeyCompletion is the ValidArgsFunction wired onto key-taking commands.
func secretKeyCompletion(opts *GlobalOpts) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return completionFromNames(func() ([]string, string, error) {
		resolved, p, err := loadProvider(opts)
		if err != nil {
			return nil, "", err
		}
		defer p.Close()
		names, err := p.ListNames(context.Background(), resolved.Path)
		if err != nil {
			return nil, "", err
		}
		return names, resolved.Path, nil
	})
}

func stripCompletionPrefix(names []string, prefix string) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		s := n
		if prefix != "" && strings.HasPrefix(s, prefix) {
			s = strings.TrimPrefix(s, prefix)
			s = strings.TrimPrefix(s, "/")
		}
		out = append(out, s)
	}
	return out
}

func filterByPrefix(names []string, toComplete string) []string {
	if toComplete == "" {
		return names
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		if strings.HasPrefix(n, toComplete) {
			out = append(out, n)
		}
	}
	return out
}
