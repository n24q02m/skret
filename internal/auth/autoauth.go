package auth

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
)

// IsAuthError classifies whether an error is auth-related and should trigger
// the auto-relogin prompt.
func IsAuthError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, substr := range []string{
		"UnauthorizedException",
		"InvalidGrantException",
		"ExpiredTokenException",
		"401",
		"403",
		"credentials missing",
		"could not resolve credentials",
		"credential not found",
	} {
		if strings.Contains(strings.ToLower(msg), strings.ToLower(substr)) {
			return true
		}
	}
	return false
}

// WithAutoAuth runs fn; on an auth-shaped error, prompts the user for inline
// login (interactive TTY only) and re-runs fn once.
func WithAutoAuth(ctx context.Context, provider string, fn func() error) error {
	return withAutoAuthIO(ctx, provider, fn, os.Stdin, os.Stderr, isNonInteractive())
}

// isNonInteractive returns true when stdin is not a terminal or SKRET_NON_INTERACTIVE=1.
func isNonInteractive() bool {
	return os.Getenv("SKRET_NON_INTERACTIVE") == "1" || !IsInteractiveStdin()
}

// withAutoAuthIO is the testable core of WithAutoAuth.
func withAutoAuthIO(ctx context.Context, provider string, fn func() error, stdin io.Reader, stderr io.Writer, nonInteractive bool) error {
	err := fn()
	if !IsAuthError(err) {
		return err
	}

	if nonInteractive {
		return fmt.Errorf("%s: credentials missing or expired; run `skret auth %s`", provider, provider)
	}

	fmt.Fprintf(stderr, "\n%s credentials missing or expired. ", provider)
	if !Confirm(stdin, stderr, "Login now?") {
		return err
	}

	if loginErr := Login(ctx, provider, nil); loginErr != nil {
		return fmt.Errorf("auth %s: %w", provider, loginErr)
	}
	return fn()
}
