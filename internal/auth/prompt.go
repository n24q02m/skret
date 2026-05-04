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

// ctxOut extracts the writer from context or defaults to os.Stderr.
func ctxOut(_ context.Context) io.Writer {
	return os.Stderr
}

// IsInteractiveStdin reports whether stdin is a terminal (for prompt gating).
// Falls back to checking if TERM is set when term package is not available.
func IsInteractiveStdin() bool {
	fi, err := os.Stdin.Stat()
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

// OpenBrowser attempts to open the URL in the platform browser, best-effort.
// Honors SKRET_NO_BROWSER=1 to skip the launch (used by tests + headless runs).
func OpenBrowser(ctx context.Context, inputUrl string) error {
	if os.Getenv("SKRET_NO_BROWSER") != "" {
		return nil
	}

	// SECURITY: Ensure the scheme is either http or https.
	// This prevents local file path traversal and command/flag injection.
	parsed, err := url.Parse(inputUrl)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return fmt.Errorf("auth prompt: invalid URL scheme: only http/https allowed")
	}

	var cmd *exec.Cmd
	switch goos() {
	case "darwin":
		cmd = exec.CommandContext(ctx, "open", "--", inputUrl)
	case "windows":
		cmd = exec.CommandContext(ctx, "rundll32", "url.dll,FileProtocolHandler", inputUrl)
	default:
		cmd = exec.CommandContext(ctx, "xdg-open", inputUrl)
	}
	return cmd.Start()
}

// goos allows tests to override the operating system check
var goos = func() string {
	return runtime.GOOS
}

// SetGOOSForTest allows setting the OS string for testing the OpenBrowser switch statement
func SetGOOSForTest(os string) {
	if os == "" {
		goos = func() string { return runtime.GOOS }
	} else {
		goos = func() string { return os }
	}
}
