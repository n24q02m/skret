package gcp

import (
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/n24q02m/skret/internal/provider"
)

// mapError translates Secret Manager errors into skret's error vocabulary:
// NotFound unwraps to provider.ErrNotFound (exit 5) and everything else
// keeps its cause under a uniform "gcp: <op> <key>" envelope (exit 3).
func mapError(op, key string, err error) error {
	if err == nil {
		return nil
	}
	if isNotFound(err) {
		return fmt.Errorf("gcp: %s %q: %w", op, key, provider.ErrNotFound)
	}
	return fmt.Errorf("gcp: %s %q: %w", op, key, err)
}

func isNotFound(err error) bool           { return statusCode(err) == codes.NotFound }
func isFailedPrecondition(err error) bool { return statusCode(err) == codes.FailedPrecondition }

func statusCode(err error) codes.Code {
	if st, ok := status.FromError(err); ok {
		return st.Code()
	}
	return codes.OK
}

// errorIsDefinitive reports whether a Set-side error definitively rejected
// the request (nothing could have committed). Transport/throttle/server
// failures return false so the caller reconciles with a readback, mirroring
// the aws provider's putErrorMayHaveCommitted.
func errorIsDefinitive(err error) bool {
	switch statusCode(err) {
	case codes.OK:
		// Not a status error (context canceled mid-flight is the common
		// case): the outcome is unknowable, so reconcile.
		return false
	case codes.InvalidArgument,
		codes.NotFound,
		codes.PermissionDenied,
		codes.AlreadyExists,
		codes.FailedPrecondition,
		codes.Unauthenticated,
		codes.OutOfRange:
		return true
	default:
		return false
	}
}
