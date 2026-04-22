package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDopplerProvider_Methods(t *testing.T) {
	p := NewDopplerProvider()
	assert.Equal(t, "doppler", p.Name())
	methods := p.Methods()
	assert.Len(t, methods, 2)
}

func TestDopplerProvider_LoginServiceToken_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer dp.st.test", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"workplace":{"name":"my-workspace"}}`))
	}))
	defer srv.Close()

	p := &DopplerProvider{baseURL: srv.URL}
	cred, err := p.Login(context.Background(), "service-token", map[string]string{
		"token": "dp.st.test",
	})
	require.NoError(t, err)
	assert.Equal(t, "service-token", cred.Method)
	assert.Equal(t, "dp.st.test", cred.Token)
	assert.Equal(t, "my-workspace", cred.Metadata["workplace"])
}

func TestDopplerProvider_LoginToken_MissingToken(t *testing.T) {
	p := NewDopplerProvider()
	_, err := p.Login(context.Background(), "service-token", map[string]string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token required")
}

func TestDopplerProvider_LoginToken_ValidationFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"message":"invalid token"}`))
	}))
	defer srv.Close()

	p := &DopplerProvider{baseURL: srv.URL}
	_, err := p.Login(context.Background(), "service-token", map[string]string{
		"token": "bad-token",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "401")
}

func TestDopplerProvider_UnknownMethod(t *testing.T) {
	p := NewDopplerProvider()
	_, err := p.Login(context.Background(), "unknown", nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrAuthMethodUnsupported)
}

func TestDopplerProvider_Validate(t *testing.T) {
	p := NewDopplerProvider()
	assert.NoError(t, p.Validate(context.Background(), &Credential{Token: "tok"}))
	assert.Error(t, p.Validate(context.Background(), nil))
	assert.Error(t, p.Validate(context.Background(), &Credential{}))
}

func TestDopplerProvider_Logout(t *testing.T) {
	p := NewDopplerProvider()
	assert.NoError(t, p.Logout(context.Background()))
}

// --- Infisical Provider ---

func TestInfisicalProvider_Methods(t *testing.T) {
	p := NewInfisicalProvider()
	assert.Equal(t, "infisical", p.Name())
	methods := p.Methods()
	assert.Len(t, methods, 2)
}

func TestInfisicalProvider_LoginUniversalAuth(t *testing.T) {
	p := NewInfisicalProvider()
	cred, err := p.Login(context.Background(), "universal-auth", map[string]string{
		"client_id":     "test-id",
		"client_secret": "test-secret",
	})
	require.NoError(t, err)
	assert.Equal(t, "universal-auth", cred.Method)
	assert.Equal(t, "test-id", cred.Metadata["client_id"])
}

func TestInfisicalProvider_LoginUniversalAuth_MissingCreds(t *testing.T) {
	p := NewInfisicalProvider()
	_, err := p.Login(context.Background(), "universal-auth", map[string]string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "client_id and client_secret required")
}

func TestInfisicalProvider_LoginToken_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer inf-test-tok", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"user":{"email":"test@example.com"}}`))
	}))
	defer srv.Close()

	p := &InfisicalProvider{baseURL: srv.URL}
	cred, err := p.Login(context.Background(), "token", map[string]string{
		"token": "inf-test-tok",
	})
	require.NoError(t, err)
	assert.Equal(t, "token", cred.Method)
	assert.Equal(t, "inf-test-tok", cred.Token)
	assert.Equal(t, "test@example.com", cred.Metadata["email"])
}

func TestInfisicalProvider_LoginToken_MissingToken(t *testing.T) {
	p := NewInfisicalProvider()
	_, err := p.Login(context.Background(), "token", map[string]string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token required")
}

func TestInfisicalProvider_LoginToken_ValidationFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"message":"forbidden"}`))
	}))
	defer srv.Close()

	p := &InfisicalProvider{baseURL: srv.URL}
	_, err := p.Login(context.Background(), "token", map[string]string{
		"token": "bad-token",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "403")
}

func TestInfisicalProvider_UnknownMethod(t *testing.T) {
	p := NewInfisicalProvider()
	_, err := p.Login(context.Background(), "unknown", nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrAuthMethodUnsupported)
}

func TestInfisicalProvider_Validate(t *testing.T) {
	p := NewInfisicalProvider()
	assert.NoError(t, p.Validate(context.Background(), &Credential{Token: "tok"}))
	assert.Error(t, p.Validate(context.Background(), nil))
	assert.Error(t, p.Validate(context.Background(), &Credential{}))
}

func TestInfisicalProvider_Logout(t *testing.T) {
	p := NewInfisicalProvider()
	assert.NoError(t, p.Logout(context.Background()))
}
