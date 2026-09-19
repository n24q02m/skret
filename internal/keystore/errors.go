package keystore

import (
	"errors"
	"fmt"
)

// Exit code values mirrored from pkg/skret (spec §7.1). Numeric duplicates
// by necessity: pkg/skret's provider registry imports provider/local, which
// imports this package, so importing pkg/skret here would cycle. The
// pkg/skret ExitCode/RemediationOf helpers recognize these errors through
// interfaces, so the values line up at the CLI boundary.
const (
	CodeGenericError    = 1
	CodeConfigError     = 2
	CodeAuthError       = 4
	CodeValidationError = 8
)

// Error is a structured keystore error carrying a spec §7.1 exit code and
// an optional remediation hint. Recognized by pkg/skret.ExitCode and
// pkg/skret.RemediationOf via interface, without an import.
type Error struct {
	Code    int
	Message string
	Err     error
	Hint    string
}

func (e *Error) Error() string {
	if e.Err != nil {
		return e.Message + ": " + e.Err.Error()
	}
	return e.Message
}

func (e *Error) Unwrap() error { return e.Err }

// ExitCode implements the interface pkg/skret.ExitCode honors.
func (e *Error) ExitCode() int { return e.Code }

// Remediation implements the interface pkg/skret.RemediationOf honors.
func (e *Error) Remediation() string { return e.Hint }

func newError(code int, message string, err error) *Error {
	return &Error{Code: code, Message: message, Err: err}
}

// withRemediation attaches a copy-pasteable fix hint to err.
func withRemediation(err error, hint string) error {
	if err == nil || hint == "" {
		return err
	}
	var e *Error
	if errors.As(err, &e) {
		e.Hint = hint
		return e
	}
	return &Error{Code: CodeGenericError, Message: err.Error(), Err: err, Hint: hint}
}

// errNoKeyMaterialHint is the remediation for every missing-key failure.
const errNoKeyMaterialHint = "export SKRET_AGE_KEY=<key-material>  # or run: skret keys init"

// noKeyMaterial builds the canonical missing-key error (exit 4 + hint).
func noKeyMaterial(context string) *Error {
	return &Error{
		Code:    CodeAuthError,
		Message: fmt.Sprintf("keys: no key material available (%s)", context),
		Hint:    errNoKeyMaterialHint,
	}
}
