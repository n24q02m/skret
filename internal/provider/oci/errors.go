package oci

import (
	"errors"
	"fmt"

	"github.com/oracle/oci-go-sdk/v65/common"

	"github.com/n24q02m/skret/internal/provider"
)

// mapError translates an OCI API error into skret's provider error classes:
// 404 responses (code NotAuthorizedOrNotFound) become provider.ErrNotFound;
// everything else keeps its SDK detail under the oci: <op> "<key>" prefix.
func mapError(op, key string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, provider.ErrNotFound) {
		return fmt.Errorf("oci: %s %q: %w", op, key, provider.ErrNotFound)
	}
	var svc common.ServiceError
	if errors.As(err, &svc) && (svc.GetHTTPStatusCode() == 404 || svc.GetCode() == "NotAuthorizedOrNotFound") {
		return fmt.Errorf("oci: %s %q: %w", op, key, provider.ErrNotFound)
	}
	return fmt.Errorf("oci: %s %q: %w", op, key, err)
}

// mutationMayHaveCommitted distinguishes OCI write errors that definitively
// rejected the request (4xx validation/auth/not-found) from transport,
// throttle and server failures whose response may have been lost after the
// service committed the new version. Ambiguous outcomes are reconciled by
// readback before skret reports success or a partial commit.
func mutationMayHaveCommitted(err error) bool {
	var svc common.ServiceError
	if !errors.As(err, &svc) {
		return true
	}
	switch svc.GetHTTPStatusCode() {
	case 400, 401, 403, 404:
		return false
	default:
		return true
	}
}
