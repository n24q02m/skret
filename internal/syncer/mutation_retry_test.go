package syncer

import (
	"context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestDoMutationDoesNotReplayAmbiguousTransientStatus(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("provider response body"))
	}))
	defer srv.Close()

	resp, err := doMutation(context.Background(), srv.Client(), func() (*http.Request, error) {
		return http.NewRequest(http.MethodPut, srv.URL, http.NoBody)
	}, http.StatusNoContent)
	require.Error(t, err)
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrMutationNeedsReconciliation)
	var statusErr *HTTPStatusError
	require.ErrorAs(t, err, &statusErr)
	assert.Equal(t, http.StatusBadGateway, statusErr.StatusCode)
	assert.Equal(t, int32(1), attempts.Load())
	assert.NotContains(t, err.Error(), "provider response body")
}
