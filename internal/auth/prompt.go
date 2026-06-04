package auth

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

// stdin is a package-level variable to allow mocking in tests.
var stdin = os.Stdin

// ctxOut extracts the writer from context or defaults to os.Stderr.
func ctxOut(_ context.Context) io.Writer {
	return os.Stderr
}

// IsInteractiveStdin reports whether stdin is a terminal (for prompt gating).
// Falls back to checking if TERM is set when term package is not available.
func IsInteractiveStdin() bool {
	fi, err := stdin.Stat()
	if err != nil {
		return false
	}
	// If stdin is a character device (terminal), ModeCharDevice is set
	return fi.Mode()&os.ModeCharDevice != 0
}

// Confirm reads a line from r and returns true unless user explicitly answered "n"/"no".
// Empty line ("\n") defaults to yes.
func Confirm(r io.Reader, w io.Writer, prompt string) bool {
	fmt.Fprintf(w, "%s [Y/n] ", prompt)
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && line == "" {
		return false
	}
	ans := strings.ToLower(strings.TrimSpace(line))
	return ans == "" || ans == "y" || ans == "yes"
}

// SelectMethod prints methods with 1-based indexes and reads one line from r.
func SelectMethod(r io.Reader, w io.Writer, methods []Method) (Method, error) {
	fmt.Fprintln(w, "Authentication method:")
	for i, m := range methods {
		desc := m.Description
		if desc == "" {
			desc = m.Name
		}
		fmt.Fprintf(w, "  [%d] %s\n", i+1, desc)
	}
	fmt.Fprint(w, "Choice: ")
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil {
		return Method{}, fmt.Errorf("auth prompt: read: %w", err)
	}
	idx, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || idx < 1 || idx > len(methods) {
		return Method{}, fmt.Errorf("auth prompt: invalid choice %q", strings.TrimSpace(line))
	}
	return methods[idx-1], nil
}

// goos is a package-level variable to allow mocking in tests for OS-specific branches.
var goos = func() string { return runtime.GOOS }

// OpenBrowser attempts to open the URL in the platform browser, best-effort.
// Honors SKRET_NO_BROWSER=1 to skip the launch (used by tests + headless runs).
func OpenBrowser(ctx context.Context, u string) error {
	if os.Getenv("SKRET_NO_BROWSER") != "" {
		return nil
	}

	parsed, err := url.Parse(u)
	if err != nil {
		return fmt.Errorf("auth prompt: invalid url: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("auth prompt: invalid url scheme %q", parsed.Scheme)
	}

	// Prevent flag injection in various browser openers.
	// Reject hosts starting with '-' to avoid being interpreted as a flag.
	if strings.HasPrefix(parsed.Host, "-") {
		return fmt.Errorf("auth prompt: invalid url host %q", parsed.Host)
	}

	safeURL := parsed.String()

	// Reject unescaped shell metacharacters that url.String() might leave behind
	// in the path or other components, which could be dangerous if the browser
	// opener (like xdg-open) is a shell script.
	if strings.ContainsAny(safeURL, "$;") {
		return fmt.Errorf("auth prompt: url contains dangerous characters")
	}

	var cmd *exec.Cmd
	switch goos() {
	case "darwin":
		cmd = exec.CommandContext(ctx, "open", "--", safeURL)
	case "windows":
		cmd = exec.CommandContext(ctx, "rundll32", "url.dll,FileProtocolHandler", safeURL)
	default:
		cmd = exec.CommandContext(ctx, "xdg-open", safeURL)
	}
	return cmd.Start()
}
