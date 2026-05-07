package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

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
