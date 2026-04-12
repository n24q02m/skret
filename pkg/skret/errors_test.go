package skret

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *Error
		expected string
	}{
		{
			name: "only message",
			err: &Error{
				Message: "something went wrong",
			},
			expected: "something went wrong",
		},
		{
			name: "message with wrapped error",
			err: &Error{
				Message: "failed to process",
				Err:     errors.New("io error"),
			},
			expected: "failed to process: io error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestError_Unwrap(t *testing.T) {
	innerErr := errors.New("inner error")
	err := &Error{
		Message: "outer error",
		Err:     innerErr,
	}

	assert.Equal(t, innerErr, err.Unwrap())
	assert.Nil(t, (&Error{Message: "no error"}).Unwrap())
}

func TestNewError(t *testing.T) {
	innerErr := errors.New("inner error")
	err := NewError(ExitConfigError, "config error", innerErr)

	assert.NotNil(t, err)
	assert.Equal(t, ExitConfigError, err.Code)
	assert.Equal(t, "config error", err.Message)
	assert.Equal(t, innerErr, err.Err)
}

func TestExitCode(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected int
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: ExitSuccess,
		},
		{
			name:     "skret error",
			err:      NewError(ExitAuthError, "auth failed", nil),
			expected: ExitAuthError,
		},
		{
			name:     "wrapped skret error",
			err:      errors.Join(NewError(ExitValidationError, "validation failed", nil)),
			expected: ExitValidationError,
		},
		{
			name:     "generic error",
			err:      errors.New("generic error"),
			expected: ExitGenericError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, ExitCode(tt.err))
		})
	}
}
