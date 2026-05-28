package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInfisicalProvider_Login_Browser_Routing(t *testing.T) {
	// We want to verify that p.Login("browser", ...) actually calls the browser flow.
	// A simple way is to pass a cancelled context, which should cause it to fail
	// early in the browser flow setup or first network call.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	p := NewInfisicalProvider()
	_, err := p.Login(ctx, "browser", nil)
	require.Error(t, err)
	// Both "context canceled" (direct) or wrapped context error are acceptable
	// as long as it proves we entered the branch.
	assert.Contains(t, err.Error(), context.Canceled.Error())
}

func TestInfisicalProvider_LoginToken_Env(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer env-test-tok", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"user":{"email":"env@example.com"}}`))
	}))
	defer srv.Close()

	t.Setenv("INFISICAL_TOKEN", "env-test-tok")

	p := &InfisicalProvider{baseURL: srv.URL}
	// Pass empty opts so it falls back to environment
	cred, err := p.Login(context.Background(), "token", map[string]string{})
	require.NoError(t, err)
	assert.Equal(t, "token", cred.Method)
	assert.Equal(t, "env-test-tok", cred.Token)
	assert.Equal(t, "env@example.com", cred.Metadata["email"])
}

func TestInfisicalProvider_LoginToken_NetworkFail(t *testing.T) {
	// Point to an unreachable port
	p := &InfisicalProvider{baseURL: "http://127.0.0.1:1"}
	_, err := p.Login(context.Background(), "token", map[string]string{
		"token": "some-tok",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "validate token")
}
