package cli

import (
	"errors"
	"fmt"
	osexec "os/exec"
	"sort"
	"strings"

	skexec "github.com/n24q02m/skret/internal/exec"
	"github.com/n24q02m/skret/internal/provider"
	"github.com/n24q02m/skret/internal/redact"
	"github.com/n24q02m/skret/pkg/skret"
	"github.com/spf13/cobra"
)

// execRedacted runs the command as a child process whose stdout and stderr
// pass through a streaming redactor that masks every secret value skret
// loaded (and its common encodings) plus token-shaped strings. The child's
// exit status is returned unchanged.
func execRedacted(cmd *cobra.Command, args, env []string, secrets []*provider.Secret, path string, minLen int) error {
	binary, err := osexec.LookPath(args[0])
	if err != nil {
		return skret.NewError(skret.ExitExecError, fmt.Sprintf("run: command not found: %s", args[0]), err)
	}

	values, short := redactValues(secrets, path, minLen)
	if len(short) > 0 {
		cmd.PrintErrf("skret: --redact: %d value(s) shorter than %d bytes are not masked: %s\n",
			len(short), minLen, strings.Join(short, ", "))
	}

	set := redact.NewSet(values, minLen)
	stdout := set.NewWriter(cmd.OutOrStdout())
	stderr := set.NewWriter(cmd.ErrOrStderr())
	runErr := skexec.RunFiltered(binary, args, env, stdout, stderr)
	// Flush whatever the redactor still holds before reporting anything, so
	// the command's last line is never lost, whatever its exit status.
	flushErr := errors.Join(stdout.Close(), stderr.Close())

	if runErr != nil {
		// A non-zero exit (or, on Unix, death by signal as 128+signal) is
		// the command's own status: return it verbatim so skret exits with it.
		var coded interface{ ExitCode() int }
		if errors.As(runErr, &coded) {
			return runErr
		}
		return skret.NewError(skret.ExitExecError, "runtime error", runErr)
	}
	if flushErr != nil {
		return skret.NewError(skret.ExitExecError, "run: writing command output failed", flushErr)
	}
	return nil
}

// redactValues returns the strings to mask for secrets: each value as stored
// and as injected into the environment. Values shorter than minLen are left
// out and their env var names returned (sorted) so the caller can warn.
func redactValues(secrets []*provider.Secret, path string, minLen int) (values, short []string) {
	values = make([]string, 0, 2*len(secrets))
	for _, s := range secrets {
		switch {
		case s.Value == "":
		case len(s.Value) < minLen:
			short = append(short, KeyToEnvName(s.Key, path))
		default:
			values = append(values, s.Value, skexec.InjectedValue(s.Value))
		}
	}
	sort.Strings(short)
	return values, short
}
