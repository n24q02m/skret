package skret

import "errors"

// Standard exit codes matching spec §7.1.
const (
	ExitSuccess         = 0
	ExitGenericError    = 1
	ExitConfigError     = 2
	ExitProviderError   = 3
	ExitAuthError       = 4
	ExitNotFoundError   = 5
	ExitConflictError   = 6
	ExitNetworkError    = 7
	ExitValidationError = 8
	ExitExecError       = 125 // Matches docker/podman exec error
)

// Error represents a structured error with an associated exit code.
type Error struct {
	Code    int
	Message string
	Err     error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return e.Message + ": " + e.Err.Error()
	}
	return e.Message
}

func (e *Error) Unwrap() error {
	return e.Err
}

// NewError creates a new Error with the specified code.
func NewError(code int, message string, err error) *Error {
	return &Error{
		Code:    code,
		Message: message,
		Err:     err,
	}
}

// ExitCode returns the appropriate exit code for an error.
func ExitCode(err error) int {
	if err == nil {
		return ExitSuccess
	}
	var skretErr *Error
	if errors.As(err, &skretErr) {
		return skretErr.Code
	}
	return ExitGenericError
}
