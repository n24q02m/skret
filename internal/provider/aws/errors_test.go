package aws

import (
	"errors"
	"testing"

	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/n24q02m/skret/internal/provider"
	"github.com/stretchr/testify/assert"
)

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
			err:     &ssmtypes.ParameterNotFound{},
			wantErr: provider.ErrNotFound,
		},
		{
			name:     "ParameterAlreadyExists",
			op:       "set",
			key:      "mykey",
			err:      &ssmtypes.ParameterAlreadyExists{},
			contains: "parameter already exists",
		},
		{
			name:     "GenericError",
			op:       "get",
			key:      "mykey",
			err:      errors.New("something went wrong"),
			contains: "something went wrong",
		},
		{
			name:     "SpecialCharactersInKey",
			op:       "set",
			key:      "my key with \"quotes\"",
			err:      &ssmtypes.ParameterNotFound{},
			wantErr:  provider.ErrNotFound,
			contains: `"my key with \"quotes\""`,
		},
		{
			name:     "WrappedError",
			op:       "list",
			key:      "/path/",
			err:      errors.New("connection timeout"),
			contains: "aws: list \"/path/\": connection timeout",
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
			// Check if key is contained (either raw or quoted by %q)
			if tt.name != "SpecialCharactersInKey" {
				assert.Contains(t, got.Error(), tt.key)
			}
		})
	}
}
