package syncer

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

const (
	maxHTTPAttempts = 3
	retryBackoff     = 10 * time.Millisecond
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

// doWithRetry executes an HTTP request up to three total attempts. The
// request factory must create a fresh request each time so request bodies can
// be replayed safely. Non-success responses are closed before they are
// retried or returned as a value-free HTTPStatusError.
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
