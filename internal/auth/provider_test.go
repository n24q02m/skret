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
	assert.Len(t, methods, 3)
	names := []string{methods[0].Name, methods[1].Name, methods[2].Name}
	assert.Contains(t, names, "oauth")
	assert.Contains(t, names, "service-token")
	assert.Contains(t, names, "personal-token")
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
