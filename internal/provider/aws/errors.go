package aws

import (
	"errors"
	"fmt"

	"github.com/aws/smithy-go"
	"github.com/n24q02m/skret/internal/provider"
)

func mapError(op, key string, err error) error {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "ParameterNotFound":
			return fmt.Errorf("aws: %s %q: %w", op, key, provider.ErrNotFound)
		case "ParameterAlreadyExists":
			return fmt.Errorf("aws: %s %q: parameter already exists", op, key)
		}
	}

	return fmt.Errorf("aws: %s %q: %w", op, key, err)
}
