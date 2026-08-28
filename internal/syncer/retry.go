package syncer

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

const (
	maxHTTPAttempts = 3
	retryBackoff    = 10 * time.Millisecond
)

// HTTPStatusError reports an HTTP response status without retaining the
// response body. Provider bodies can echo sensitive values, so callers must
// never include them in returned errors.
type HTTPStatusError struct {
	StatusCode int
}

func (e *HTTPStatusError) Error() string {
	return fmt.Sprintf("status %d", e.StatusCode)
}

var ErrMutationNeedsReconciliation = errors.New("provider mutation needs reconciliation")

// MutationNeedsReconciliationError deliberately exposes only the HTTP method
// and status/category. Its cause remains inspectable for typed status/context
// checks, but provider response bodies are never retained.
type MutationNeedsReconciliationError struct {
	Method     string
	StatusCode int
	Cause      error
}

func (e *MutationNeedsReconciliationError) Error() string {
	if e == nil {
		return ErrMutationNeedsReconciliation.Error()
	}
	if e.StatusCode > 0 {
		return fmt.Sprintf("%s mutation needs reconciliation after status %d", e.Method, e.StatusCode)
	}
	return fmt.Sprintf("%s mutation needs reconciliation after transport failure", e.Method)
}

func (e *MutationNeedsReconciliationError) Unwrap() error {
	if e == nil {
		return ErrMutationNeedsReconciliation
	}
	return e.Cause
}

func (e *MutationNeedsReconciliationError) Is(target error) bool {
	return target == ErrMutationNeedsReconciliation
}

func isTransientHTTPStatus(status int) bool {
	switch status {
	case http.StatusRequestTimeout, 425, http.StatusTooManyRequests,
		http.StatusInternalServerError, http.StatusBadGateway,
		http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

// doWithRetry executes an HTTP read up to three total attempts. The request
// factory must create a fresh request each time. Mutation callers must use
// doMutation instead because a transient response cannot prove no side effect.
func doWithRetry(
	ctx context.Context,
	client *http.Client,
	newRequest func() (*http.Request, error),
	successStatuses ...int,
) (*http.Response, error) {
	for attempt := range maxHTTPAttempts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		req, err := newRequest()
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			return nil, err
		}
		if statusAllowed(resp.StatusCode, successStatuses) {
			return resp, nil
		}

		status := resp.StatusCode
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
		if !isTransientHTTPStatus(status) || attempt == maxHTTPAttempts-1 {
			return nil, &HTTPStatusError{StatusCode: status}
		}
		if err := waitForRetry(ctx, retryBackoff*time.Duration(1<<attempt)); err != nil {
			return nil, err
		}
	}
	return nil, ctx.Err()
}

// doMutation performs exactly one provider mutation attempt. A response status
// cannot prove that a remote PUT/PATCH had no side effect, so transient
// responses and transport failures are returned without replaying the request.
// Callers must persist their operation identity before calling this function
// and reconcile through the provider's read path before any explicit retry.
func doMutation(
	ctx context.Context,
	client *http.Client,
	newRequest func() (*http.Request, error),
	successStatuses ...int,
) (*http.Response, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	req, err := newRequest()
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, &MutationNeedsReconciliationError{Method: req.Method, Cause: ctxErr}
		}
		return nil, &MutationNeedsReconciliationError{Method: req.Method, Cause: err}
	}
	if statusAllowed(resp.StatusCode, successStatuses) {
		return resp, nil
	}
	status := resp.StatusCode
	if resp.Body != nil {
		_ = resp.Body.Close()
	}
	return nil, &MutationNeedsReconciliationError{
		Method:     req.Method,
		StatusCode: status,
		Cause:      &HTTPStatusError{StatusCode: status},
	}
}

func statusAllowed(status int, successStatuses []int) bool {
	for _, success := range successStatuses {
		if status == success {
			return true
		}
	}
	return false
}

func waitForRetry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
