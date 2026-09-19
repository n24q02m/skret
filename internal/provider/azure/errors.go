package azure

import (
	"errors"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"

	"github.com/n24q02m/skret/internal/provider"
)

func mapError(op, key string, err error) error {
	var respErr *azcore.ResponseError
	if errors.As(err, &respErr) {
		switch respErr.ErrorCode {
		case "SecretNotFound", "NotFound":
			return fmt.Errorf("azure: %s %q: %w", op, key, provider.ErrNotFound)
		}
	}
	return fmt.Errorf("azure: %s %q: %w", op, key, err)
}

func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	var respErr *azcore.ResponseError
	if errors.As(err, &respErr) {
		switch respErr.ErrorCode {
		case "SecretNotFound", "NotFound":
			return true
		}
		return respErr.StatusCode == 404
	}
	return false
}

// setErrorMayHaveCommitted mirrors the AWS provider's
// putErrorMayHaveCommitted: definite 4xx rejects prove nothing committed;
// 5xx and transport-level failures (no *azcore.ResponseError at all) leave
// the outcome ambiguous and require readback reconciliation.
func setErrorMayHaveCommitted(err error) bool {
	var respErr *azcore.ResponseError
	if !errors.As(err, &respErr) {
		return true
	}
	return respErr.StatusCode >= 500
}
