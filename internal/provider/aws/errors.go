package aws

import (
	"errors"
	"fmt"

	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/n24q02m/skret/internal/provider"
)

func mapError(op, key string, err error) error {
	var notFound *ssmtypes.ParameterNotFound
	if errors.As(err, &notFound) {
		return fmt.Errorf("aws: %s %q: %w", op, key, provider.ErrNotFound)
	}

	var alreadyExists *ssmtypes.ParameterAlreadyExists
	if errors.As(err, &alreadyExists) {
		return fmt.Errorf("aws: %s %q: parameter already exists", op, key)
	}

	return fmt.Errorf("aws: %s %q: %w", op, key, err)
}
