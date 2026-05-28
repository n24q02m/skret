package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewInfisicalProvider_Env(t *testing.T) {
	const customURL = "https://infisical.example.com"
	t.Setenv("INFISICAL_API_URL", customURL)
	p := NewInfisicalProvider()
	assert.Equal(t, customURL, p.baseURL)

	t.Setenv("INFISICAL_API_URL", "")
	p2 := NewInfisicalProvider()
	assert.Equal(t, "https://app.infisical.com", p2.baseURL)
}

func TestInfisicalProvider_Login_BrowserDispatch(t *testing.T) {
	p := NewInfisicalProvider()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := p.Login(ctx, "browser", nil)
	require.Error(t, err)
	// We just want to see it reached the browser flow which starts by generating state/pkce.
	// Since context is canceled, it should fail early in randomString or similar.
	assert.Contains(t, err.Error(), "context canceled")
}

func TestInfisicalProvider_ErrorBranches(t *testing.T) {
	// Use a malformed URL to trigger NewRequest error
	// "%%" is an invalid URL escape sequence.
	p := &InfisicalProvider{baseURL: "%%"}

	t.Run("UniversalAuth_NewRequestError", func(t *testing.T) {
		_, err := p.loginUniversalAuth(context.Background(), map[string]string{
			"client_id": "a", "client_secret": "b",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "build request")
	})

	t.Run("Token_NewRequestError", func(t *testing.T) {
		_, err := p.loginToken(context.Background(), map[string]string{
			"token": "tok",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "create request")
	})
}

func TestInfisicalProvider_LoginToken_ClientDoError(t *testing.T) {
	// Base URL that will fail at client.Do
	p := &InfisicalProvider{baseURL: "http://127.0.0.1:1"}
	_, err := p.loginToken(context.Background(), map[string]string{
		"token": "tok",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "validate token")
}
