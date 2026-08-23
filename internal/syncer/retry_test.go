package syncer

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"
	"sync/atomic"
	"testing"

	"github.com/n24q02m/skret/internal/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/nacl/box"
)

type trackingBody struct {
	io.ReadCloser
	closed *atomic.Int32
}

func (b *trackingBody) Close() error {
	b.closed.Add(1)
	return b.ReadCloser.Close()
}

type trackingTransport struct {
	base   http.RoundTripper
	closed *atomic.Int32
}

func (t *trackingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	resp.Body = &trackingBody{ReadCloser: resp.Body, closed: t.closed}
	return resp, nil
}

func retryTestClient(srv *httptest.Server, closed *atomic.Int32) *http.Client {
	return &http.Client{
		Transport: &trackingTransport{base: srv.Client().Transport, closed: closed},
	}
}

func retryTestRequest(ctx context.Context, method, endpoint string) (*http.Request, error) {
	return http.NewRequestWithContext(ctx, method, endpoint, http.NoBody)
}

func TestDoWithRetry_TransientThenSuccess(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if attempts.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("transient body"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	var closed atomic.Int32
	ctx := context.Background()
	resp, err := doWithRetry(ctx, retryTestClient(srv, &closed), func() (*http.Request, error) {
		return retryTestRequest(ctx, http.MethodGet, srv.URL)
	}, http.StatusOK)
	require.NoError(t, err)
	body, readErr := io.ReadAll(resp.Body)
	require.NoError(t, readErr)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, "ok", string(body))
	assert.Equal(t, int32(2), attempts.Load())
	assert.Equal(t, int32(2), closed.Load())
}

func TestDoWithRetry_ExhaustsTransientStatusWithoutBodyLeakage(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("sensitive-provider-body"))
	}))
	defer srv.Close()

	var closed atomic.Int32
	ctx := context.Background()
	_, err := doWithRetry(ctx, retryTestClient(srv, &closed), func() (*http.Request, error) {
		return retryTestRequest(ctx, http.MethodGet, srv.URL)
	}, http.StatusOK)
	require.Error(t, err)
	var statusErr *HTTPStatusError
	require.ErrorAs(t, err, &statusErr)
	assert.Equal(t, http.StatusBadGateway, statusErr.StatusCode)
	assert.NotContains(t, err.Error(), "sensitive-provider-body")
	assert.Equal(t, int32(3), attempts.Load())
	assert.Equal(t, int32(3), closed.Load())
}

func TestDoWithRetry_PermanentStatusDoesNotRetry(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("secret auth response"))
	}))
	defer srv.Close()

	var closed atomic.Int32
	ctx := context.Background()
	_, err := doWithRetry(ctx, retryTestClient(srv, &closed), func() (*http.Request, error) {
		return retryTestRequest(ctx, http.MethodGet, srv.URL)
	}, http.StatusOK)
	require.Error(t, err)
	var statusErr *HTTPStatusError
	require.ErrorAs(t, err, &statusErr)
	assert.Equal(t, http.StatusUnauthorized, statusErr.StatusCode)
	assert.NotContains(t, err.Error(), "secret auth response")
	assert.Equal(t, int32(1), attempts.Load())
	assert.Equal(t, int32(1), closed.Load())
}

func TestDoWithRetry_ContextCancellationStopsBackoff(t *testing.T) {
	var attempts atomic.Int32
	firstResponse := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
		close(firstResponse)
	}))
	defer srv.Close()

	var closed atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-firstResponse
		time.Sleep(5 * time.Millisecond)
		cancel()
	}()

	_, err := doWithRetry(ctx, retryTestClient(srv, &closed), func() (*http.Request, error) {
		return retryTestRequest(ctx, http.MethodGet, srv.URL)
	}, http.StatusOK)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, int32(1), attempts.Load())
	assert.Equal(t, int32(1), closed.Load())
}

func TestTransientHTTPStatusClassification(t *testing.T) {
	for _, status := range []int{http.StatusRequestTimeout, 425, http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout} {
		assert.True(t, isTransientHTTPStatus(status), "status %d", status)
	}
	for _, status := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusConflict, http.StatusTeapot} {
		assert.False(t, isTransientHTTPStatus(status), "status %d", status)
	}
}

func TestGitHubSyncer_RetriesGETAndPUT(t *testing.T) {
	var getAttempts, putAttempts atomic.Int32
	pubKey, _, err := box.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey[:])
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if getAttempts.Add(1) == 1 {
				w.WriteHeader(http.StatusGatewayTimeout)
				return
			}
			_, _ = w.Write([]byte(`{"key_id":"id","key":"` + pubKeyB64 + `"}`))
		case http.MethodPut:
			if putAttempts.Add(1) == 1 {
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	g := NewGitHub("owner", "repo", "token", srv.URL).(*GitHubSyncer)
	var closed atomic.Int32
	g.httpClient = retryTestClient(srv, &closed)
	gotKey, gotID, err := g.getPublicKey(context.Background())
	require.NoError(t, err)
	assert.Equal(t, pubKeyB64, gotKey)
	assert.Equal(t, "id", gotID)
	var recipientKey [32]byte
	copy(recipientKey[:], pubKey[:])
	require.NoError(t, g.putSecret(context.Background(), "NAME", "value", &recipientKey, "id"))
	assert.Equal(t, int32(2), getAttempts.Load())
	assert.Equal(t, int32(2), putAttempts.Load())
	assert.Equal(t, int32(4), closed.Load())
}

func TestGitHubSyncer_RetriesExistingKeysGET(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		if attempts.Add(1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte(`{"total_count":1,"secrets":[{"name":"NAME"}]}`))
	}))
	defer srv.Close()

	g := NewGitHub("owner", "repo", "token", srv.URL).(*GitHubSyncer)
	names, err := g.ExistingKeys(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"NAME"}, names)
	assert.Equal(t, int32(2), attempts.Load())
}

func TestCloudflareSyncer_RetriesPUTPATCHAndGET(t *testing.T) {
	var putAttempts, patchAttempts, getAttempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut:
			if putAttempts.Add(1) == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusOK)
		case http.MethodPatch:
			if patchAttempts.Add(1) == 1 {
				w.WriteHeader(http.StatusRequestTimeout)
				return
			}
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			if getAttempts.Add(1) == 1 {
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			_, _ = w.Write([]byte(`{"result":[{"name":"NAME"}]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	var closed atomic.Int32
	client := retryTestClient(srv, &closed)
	worker := NewCloudflare("account", "worker", "", "token", srv.URL).(*CloudflareSyncer)
	worker.httpClient = client
	require.NoError(t, worker.Sync(context.Background(), []*provider.Secret{{Key: "NAME", Value: "value"}}))
	names, err := worker.ExistingKeys(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"NAME"}, names)

	pages := NewCloudflare("account", "", "pages", "token", srv.URL).(*CloudflareSyncer)
	pages.httpClient = client
	require.NoError(t, pages.Sync(context.Background(), []*provider.Secret{{Key: "NAME", Value: "value"}}))
	assert.Equal(t, int32(2), putAttempts.Load())
	assert.Equal(t, int32(2), patchAttempts.Load())
	assert.Equal(t, int32(2), getAttempts.Load())
	assert.Equal(t, int32(6), closed.Load())
}

func TestHTTPStatusErrorHasNoWrappedBody(t *testing.T) {
	err := &HTTPStatusError{StatusCode: http.StatusForbidden}
	assert.Equal(t, "status 403", err.Error())
	assert.NotContains(t, err.Error(), "value")
	assert.False(t, errors.Is(err, context.Canceled))
	assert.False(t, strings.Contains(err.Error(), "body"))
}
