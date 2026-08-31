package syncer

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type roundTripFuncCov func(req *http.Request) (*http.Response, error)

func (f roundTripFuncCov) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestDoMutationRetryExhaustsMaxRetries(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	<-ctx.Done()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPut, "http://localhost", http.NoBody)
	resp, err := doMutation(ctx, http.DefaultClient, func() (*http.Request, error) { return req, nil }, http.StatusNoContent)
	assert.Error(t, err)
	assert.Nil(t, resp)
}

func TestMutationNeedsReconciliationError_Nil(t *testing.T) {
	var err *MutationNeedsReconciliationError
	assert.Equal(t, "provider mutation needs reconciliation", err.Error())
	assert.Equal(t, ErrMutationNeedsReconciliation, err.Unwrap())
}

func TestMutationNeedsReconciliationError_TransportFailure(t *testing.T) {
	err := &MutationNeedsReconciliationError{Method: http.MethodPut}
	assert.Equal(t, "PUT mutation needs reconciliation after transport failure", err.Error())
}

func TestDoWithRetry_ContextCancelledBeforeRequest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	resp, err := doWithRetry(ctx, http.DefaultClient, func() (*http.Request, error) { return nil, assert.AnError }, http.StatusOK)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Nil(t, resp)
}

func TestDoWithRetry_NewRequestFails(t *testing.T) {
	resp, err := doWithRetry(context.Background(), http.DefaultClient, func() (*http.Request, error) { return nil, assert.AnError }, http.StatusOK)
	assert.ErrorIs(t, err, assert.AnError)
	assert.Nil(t, resp)
}

func TestDoMutation_ContextCancelledBeforeRequest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	resp, err := doMutation(ctx, http.DefaultClient, func() (*http.Request, error) { return nil, assert.AnError }, http.StatusOK)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Nil(t, resp)
}

func TestDoMutation_NewRequestFails(t *testing.T) {
	resp, err := doMutation(context.Background(), http.DefaultClient, func() (*http.Request, error) { return nil, assert.AnError }, http.StatusOK)
	assert.ErrorIs(t, err, assert.AnError)
	assert.Nil(t, resp)
}

func TestDoMutation_ContextCancelledDuringRequest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	client := &http.Client{Transport: roundTripFuncCov(func(req *http.Request) (*http.Response, error) { cancel(); return nil, assert.AnError })}
	resp, err := doMutation(ctx, client, func() (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodPut, "http://localhost", http.NoBody)
	}, http.StatusOK)
	assert.Error(t, err)
	var mnre *MutationNeedsReconciliationError
	require.ErrorAs(t, err, &mnre)
	assert.ErrorIs(t, mnre.Cause, context.Canceled)
	assert.Nil(t, resp)
}

func TestDoWithRetry_ContextCancelledDuringRequest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	client := &http.Client{Transport: roundTripFuncCov(func(req *http.Request) (*http.Response, error) { cancel(); return nil, assert.AnError })}
	resp, err := doWithRetry(ctx, client, func() (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", http.NoBody)
	}, http.StatusOK)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Nil(t, resp)
}

func TestDoWithRetry_ContextCancelledDuringDelay(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	client := &http.Client{Transport: roundTripFuncCov(func(req *http.Request) (*http.Response, error) {
		go func() { time.Sleep(5 * time.Millisecond); cancel() }()
		return &http.Response{StatusCode: http.StatusBadGateway}, nil
	})}
	resp, err := doWithRetry(ctx, client, func() (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", http.NoBody)
	}, http.StatusOK)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Nil(t, resp)
}

func TestDoWithRetry_NonTransientError(t *testing.T) {
	client := &http.Client{Transport: roundTripFuncCov(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusForbidden}, nil
	})}
	resp, err := doWithRetry(context.Background(), client, func() (*http.Request, error) {
		return http.NewRequestWithContext(context.Background(), http.MethodGet, "http://localhost", http.NoBody)
	}, http.StatusOK)
	assert.Error(t, err)
	var httpErr *HTTPStatusError
	require.ErrorAs(t, err, &httpErr)
	assert.Equal(t, http.StatusForbidden, httpErr.StatusCode)
	assert.Nil(t, resp)
}

func TestDoWithRetry_TransientErrorExhaustsRetries(t *testing.T) {
	client := &http.Client{Transport: roundTripFuncCov(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusBadGateway}, nil
	})}
	resp, err := doWithRetry(context.Background(), client, func() (*http.Request, error) {
		return http.NewRequestWithContext(context.Background(), http.MethodGet, "http://localhost", http.NoBody)
	}, http.StatusOK)
	assert.Error(t, err)
	var httpErr *HTTPStatusError
	require.ErrorAs(t, err, &httpErr)
	assert.Equal(t, http.StatusBadGateway, httpErr.StatusCode)
	assert.Nil(t, resp)
}

func TestDoWithRetry_TransientErrorThenSuccess(t *testing.T) {
	attempts := 0
	client := &http.Client{Transport: roundTripFuncCov(func(req *http.Request) (*http.Response, error) {
		attempts++
		if attempts < 2 {
			return &http.Response{StatusCode: http.StatusBadGateway}, nil
		}
		return &http.Response{StatusCode: http.StatusOK}, nil
	})}
	resp, err := doWithRetry(context.Background(), client, func() (*http.Request, error) {
		return http.NewRequestWithContext(context.Background(), http.MethodGet, "http://localhost", http.NoBody)
	}, http.StatusOK)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestDoMutation_NonTransientError(t *testing.T) {
	client := &http.Client{Transport: roundTripFuncCov(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusForbidden}, nil
	})}
	resp, err := doMutation(context.Background(), client, func() (*http.Request, error) {
		return http.NewRequestWithContext(context.Background(), http.MethodPut, "http://localhost", http.NoBody)
	}, http.StatusOK)
	assert.Error(t, err)
	var mnre *MutationNeedsReconciliationError
	require.ErrorAs(t, err, &mnre)
	assert.Equal(t, http.StatusForbidden, mnre.StatusCode)
	var httpErr *HTTPStatusError
	require.ErrorAs(t, err, &httpErr)
	assert.Equal(t, http.StatusForbidden, httpErr.StatusCode)
	assert.Nil(t, resp)
}

func TestMutationNeedsReconciliationError_Error(t *testing.T) {
	var err *MutationNeedsReconciliationError
	assert.Equal(t, "provider mutation needs reconciliation", err.Error())

	err = &MutationNeedsReconciliationError{Method: http.MethodGet}
	assert.Equal(t, "GET mutation needs reconciliation after transport failure", err.Error())

	err = &MutationNeedsReconciliationError{Method: http.MethodGet, StatusCode: 500}
	assert.Equal(t, "GET mutation needs reconciliation after status 500", err.Error())
}

func TestMutationNeedsReconciliationError_Unwrap(t *testing.T) {
	var err *MutationNeedsReconciliationError
	assert.Equal(t, ErrMutationNeedsReconciliation, err.Unwrap())

	cause := assert.AnError
	err = &MutationNeedsReconciliationError{Cause: cause}
	assert.Equal(t, cause, err.Unwrap())
}

func TestMutationNeedsReconciliationError_Is(t *testing.T) {
	var err *MutationNeedsReconciliationError
	assert.True(t, err.Is(ErrMutationNeedsReconciliation))
	assert.False(t, err.Is(assert.AnError))
}

func TestIsTransientHTTPStatus(t *testing.T) {
	assert.True(t, isTransientHTTPStatus(http.StatusRequestTimeout))
	assert.True(t, isTransientHTTPStatus(425))
	assert.True(t, isTransientHTTPStatus(http.StatusTooManyRequests))
	assert.True(t, isTransientHTTPStatus(http.StatusInternalServerError))
	assert.True(t, isTransientHTTPStatus(http.StatusBadGateway))
	assert.True(t, isTransientHTTPStatus(http.StatusServiceUnavailable))
	assert.True(t, isTransientHTTPStatus(http.StatusGatewayTimeout))
	assert.False(t, isTransientHTTPStatus(http.StatusOK))
	assert.False(t, isTransientHTTPStatus(http.StatusNotFound))
}

func TestStatusAllowed(t *testing.T) {
	assert.True(t, statusAllowed(http.StatusOK, []int{http.StatusOK, http.StatusCreated}))
	assert.True(t, statusAllowed(http.StatusCreated, []int{http.StatusOK, http.StatusCreated}))
	assert.False(t, statusAllowed(http.StatusAccepted, []int{http.StatusOK, http.StatusCreated}))
}

func TestDoMutation_ContextErrorDuringDo(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	client := &http.Client{Transport: roundTripFuncCov(func(req *http.Request) (*http.Response, error) { cancel(); return nil, assert.AnError })}
	resp, err := doMutation(ctx, client, func() (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", http.NoBody)
	}, http.StatusOK)
	assert.Error(t, err)
	var mnre *MutationNeedsReconciliationError
	require.ErrorAs(t, err, &mnre)
	assert.ErrorIs(t, mnre.Cause, context.Canceled)
	assert.Nil(t, resp)
}

func TestDoWithRetry_ContextErrorDuringDo(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	client := &http.Client{Transport: roundTripFuncCov(func(req *http.Request) (*http.Response, error) { cancel(); return nil, assert.AnError })}
	resp, err := doWithRetry(ctx, client, func() (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", http.NoBody)
	}, http.StatusOK)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Nil(t, resp)
}

func TestDoWithRetry_ContextErrorDuringDelay(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	client := &http.Client{Transport: roundTripFuncCov(func(req *http.Request) (*http.Response, error) {
		go func() {
			time.Sleep(5 * time.Millisecond)
			cancel()
		}()
		return &http.Response{StatusCode: http.StatusBadGateway}, nil
	})}
	resp, err := doWithRetry(ctx, client, func() (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", http.NoBody)
	}, http.StatusOK)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Nil(t, resp)
}

func TestDoWithRetry_ContextCancelledAfterTransientError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	client := &http.Client{Transport: roundTripFuncCov(func(req *http.Request) (*http.Response, error) {
		cancel() // cancel so wait for retry fails
		return &http.Response{StatusCode: http.StatusBadGateway}, nil
	})}
	resp, err := doWithRetry(ctx, client, func() (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", http.NoBody)
	}, http.StatusOK)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Nil(t, resp)
}
