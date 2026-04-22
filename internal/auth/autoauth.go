package auth

import (
	"context"
	"fmt"
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
	err := fn()
	if !IsAuthError(err) {
		return err
	}

	nonInteractive := os.Getenv("SKRET_NON_INTERACTIVE") == "1" || !IsInteractiveStdin()
	if nonInteractive {
		return fmt.Errorf("%s: credentials missing or expired; run `skret auth %s`", provider, provider)
	}

	fmt.Fprintf(os.Stderr, "\n%s credentials missing or expired. ", provider)
	if !Confirm(os.Stdin, os.Stderr, "Login now?") {
		return err
	}

	if loginErr := Login(ctx, provider, nil); loginErr != nil {
		return fmt.Errorf("auth %s: %w", provider, loginErr)
	}
	return fn()
}
