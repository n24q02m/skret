package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockDopplerOAuth struct {
	loginFunc func(ctx context.Context, opts map[string]string) (*Credential, error)
}

func (m *mockDopplerOAuth) Login(ctx context.Context, opts map[string]string) (*Credential, error) {
	return m.loginFunc(ctx, opts)
}

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

	p := &dopplerProvider{baseURL: srv.URL}
	cred, err := p.Login(context.Background(), "service-token", map[string]string{
		"token": "dp.st.test",
	})
	require.NoError(t, err)
	assert.Equal(t, "service-token", cred.Method)
	assert.Equal(t, "dp.st.test", cred.Token)
	assert.Equal(t, "my-workspace", cred.Metadata["workplace"])
}

func TestDopplerProvider_LoginPersonalToken_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer dp.pt.test", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"workplace":{"name":"my-workspace"}}`))
	}))
	defer srv.Close()

	p := &dopplerProvider{baseURL: srv.URL}
	cred, err := p.Login(context.Background(), "personal-token", map[string]string{
		"token": "dp.pt.test",
	})
	require.NoError(t, err)
	assert.Equal(t, "personal-token", cred.Method)
}

func TestDopplerProvider_LoginToken_EnvFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"workplace":{"name":"env-workspace"}}`))
	}))
	defer srv.Close()

	t.Setenv("DOPPLER_TOKEN", "dp.env.test")
	p := &dopplerProvider{baseURL: srv.URL}
	cred, err := p.Login(context.Background(), "service-token", nil)
	require.NoError(t, err)
	assert.Equal(t, "dp.env.test", cred.Token)
}

func TestDopplerProvider_LoginToken_MissingToken(t *testing.T) {
	t.Setenv("DOPPLER_TOKEN", "")
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

	p := &dopplerProvider{baseURL: srv.URL}
	_, err := p.Login(context.Background(), "service-token", map[string]string{
		"token": "bad-token",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "401")
}

func TestDopplerProvider_LoginToken_NetworkError(t *testing.T) {
	p := &dopplerProvider{baseURL: "http://127.0.0.1:1"}
	_, err := p.Login(context.Background(), "service-token", map[string]string{
		"token": "tok",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "validate token")
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

func TestDopplerProvider_LoginOAuth_Mock(t *testing.T) {
	mock := &mockDopplerOAuth{
		loginFunc: func(ctx context.Context, opts map[string]string) (*Credential, error) {
			return &Credential{Token: "mock-token", Method: "oauth"}, nil
		},
	}
	p := &dopplerProvider{oauth: mock}
	cred, err := p.Login(context.Background(), "oauth", nil)
	require.NoError(t, err)
	assert.Equal(t, "mock-token", cred.Token)
}

func TestDopplerProvider_LoginOAuth_MockError(t *testing.T) {
	mock := &mockDopplerOAuth{
		loginFunc: func(ctx context.Context, opts map[string]string) (*Credential, error) {
			return nil, errors.New("mock error")
		},
	}
	p := &dopplerProvider{oauth: mock}
	_, err := p.Login(context.Background(), "oauth", nil)
	require.Error(t, err)
	assert.Equal(t, "mock error", err.Error())
}

func TestDopplerProvider_OAuthDispatchSuccess_EndToEnd(t *testing.T) {
	polls := 0
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v3/auth/device":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code": "c", "auth_url": srv.URL + "/approve",
				"polling_interval": 1, "expires_in": 60,
			})
		case "/v3/auth/device/token":
			polls++
			if polls < 2 {
				w.WriteHeader(http.StatusAccepted)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"token": "dp.ok", "name": "x@y",
			})
		}
	}))
	defer srv.Close()

	flow := NewDopplerOAuthFlow(srv.URL)
	flow.PollInterval = 10 * time.Millisecond
	flow.Opener = func(context.Context, string) error { return nil }

	p := &dopplerProvider{
		baseURL: srv.URL,
		oauth:   flow,
	}
	cred, err := p.Login(context.Background(), "oauth", nil)
	require.NoError(t, err)
	assert.Equal(t, "dp.ok", cred.Token)
}
