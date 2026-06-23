package aws

import (
	"errors"
	"testing"

	"github.com/aws/smithy-go"
	"github.com/n24q02m/skret/internal/provider"
	"github.com/stretchr/testify/assert"
)

type mockAPIError struct {
	code    string
	message string
}

func (e *mockAPIError) Error() string                 { return e.message }
func (e *mockAPIError) ErrorCode() string             { return e.code }
func (e *mockAPIError) ErrorMessage() string          { return e.message }
func (e *mockAPIError) ErrorFault() smithy.ErrorFault { return smithy.FaultClient }

func TestMapError(t *testing.T) {
	tests := []struct {
		name     string
		op       string
		key      string
		err      error
		wantErr  error
		contains string
	}{
		{
			name:    "ParameterNotFound",
			op:      "get",
			key:     "mykey",
			err:     &mockAPIError{code: "ParameterNotFound"},
			wantErr: provider.ErrNotFound,
		},
		{
			name:     "ParameterAlreadyExists",
			op:       "set",
			key:      "mykey",
			err:      &mockAPIError{code: "ParameterAlreadyExists"},
			contains: "parameter already exists",
		},
		{
			name:     "GenericError",
			op:       "get",
			key:      "mykey",
			err:      errors.New("something went wrong"),
			contains: "something went wrong",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapError(tt.op, tt.key, tt.err)
			if tt.wantErr != nil {
				assert.ErrorIs(t, got, tt.wantErr)
			}
			if tt.contains != "" {
				assert.Contains(t, got.Error(), tt.contains)
			}
			assert.Contains(t, got.Error(), tt.op)
			assert.Contains(t, got.Error(), tt.key)
		})
	}
}
