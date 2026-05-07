package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type errorReader struct{}

func (e *errorReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("rand error")
}

func TestPkcePair_Error(t *testing.T) {
	oldRand := randReader
	randReader = &errorReader{}
	defer func() { randReader = oldRand }()

	_, _, err := pkcePair()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rand error")
}

func TestInfisicalBrowserFlow_Login_PkceError(t *testing.T) {
	oldRand := randReader
	randReader = &errorReader{}
	defer func() { randReader = oldRand }()

	flow := NewInfisicalBrowserFlow("")
	_, err := flow.Login(context.Background(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "infisical browser: pkce")
}

func TestInfisicalBrowserFlow_ExchangeToken_NewRequestError(t *testing.T) {
	flow := NewInfisicalBrowserFlow("http://[::1]:namedport")
	_, err := flow.exchangeToken(context.Background(), "code", "verifier")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "build request")
}

func TestInfisicalBrowserFlow_ExchangeToken_NetworkError(t *testing.T) {
	flow := NewInfisicalBrowserFlow("http://127.0.0.1:1")
	_, err := flow.exchangeToken(context.Background(), "code", "verifier")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token exchange")
}

func TestInfisicalBrowserFlow_ExchangeToken_StatusError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	flow := NewInfisicalBrowserFlow(srv.URL)
	_, err := flow.exchangeToken(context.Background(), "code", "verifier")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token status 403")
}

func TestInfisicalBrowserFlow_WaitForCode_ListenError(t *testing.T) {
	oldAddr := loopbackAddr
	loopbackAddr = "invalid-address"
	defer func() { loopbackAddr = oldAddr }()

	flow := NewInfisicalBrowserFlow("")
	_, err := flow.waitForCode(context.Background(), "challenge")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "infisical browser: listen")
}

func TestInfisicalBrowserFlow_WaitForCode_Timeout(t *testing.T) {
	oldTimeout := callbackTimeout
	callbackTimeout = 1 * time.Millisecond
	defer func() { callbackTimeout = oldTimeout }()

	flow := NewInfisicalBrowserFlow("")
	flow.Opener = func(ctx context.Context, authURL string) error { return nil }

	_, err := flow.waitForCode(context.Background(), "challenge")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "infisical browser: callback timeout")
}

func TestInfisicalBrowserFlow_ExchangeToken_MarshalError(t *testing.T) {
	oldMarshal := marshalJSON
	marshalJSON = func(v interface{}) ([]byte, error) {
		return nil, errors.New("marshal error")
	}
	defer func() { marshalJSON = oldMarshal }()

	flow := NewInfisicalBrowserFlow("")
	_, err := flow.exchangeToken(context.Background(), "code", "verifier")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "infisical browser: marshal body: marshal error")
}
