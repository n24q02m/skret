package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInfisicalProvider_Methods(t *testing.T) {
	p := NewInfisicalProvider()
	assert.Equal(t, "infisical", p.Name())
	methods := p.Methods()
	assert.Len(t, methods, 3)
	names := []string{methods[0].Name, methods[1].Name, methods[2].Name}
	assert.Contains(t, names, "browser")
	assert.Contains(t, names, "universal-auth")
	assert.Contains(t, names, "token")
}

func TestInfisicalProvider_LoginUniversalAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"accessToken":"ua-access-token"}`))
	}))
	defer srv.Close()

	p := &InfisicalProvider{baseURL: srv.URL}
	cred, err := p.Login(context.Background(), "universal-auth", map[string]string{
		"client_id":     "test-id",
		"client_secret": "test-secret",
	})
	require.NoError(t, err)
	assert.Equal(t, "universal-auth", cred.Method)
	assert.Equal(t, "ua-access-token", cred.Token)
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

// --- Coverage & Edge Cases ---

func TestInfisicalProvider_LoginUniversalAuth_Non2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"nope"}`))
	}))
	defer srv.Close()

	p := &InfisicalProvider{baseURL: srv.URL}
	_, err := p.Login(context.Background(), "universal-auth", map[string]string{
		"client_id": "a", "client_secret": "b",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "401")
}

func TestInfisicalProvider_LoginUniversalAuth_NetworkFail(t *testing.T) {
	p := &InfisicalProvider{baseURL: "http://127.0.0.1:1"}
	_, err := p.Login(context.Background(), "universal-auth", map[string]string{
		"client_id": "a", "client_secret": "b",
	})
	require.Error(t, err)
}

func TestInfisicalProvider_LoginUniversalAuth_DecodeFail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{not-json`))
	}))
	defer srv.Close()

	p := &InfisicalProvider{baseURL: srv.URL}
	_, err := p.Login(context.Background(), "universal-auth", map[string]string{
		"client_id": "a", "client_secret": "b",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode")
}

func TestInfisicalBrowserFlow_TokenStatusNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/auth/token" {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	flow := NewInfisicalBrowserFlow(srv.URL)
	flow.Opener = func(bgctx context.Context, authURL string) error {
		go func() {
			time.Sleep(50 * time.Millisecond)
			cb := extractCallbackURL(authURL)
			if cb == "" {
				return
			}
			hitCallback(bgctx, cb+"?code=c")
		}()
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := flow.Login(ctx, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "502")
}

func TestInfisicalBrowserFlow_MissingCodeCallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()

	flow := NewInfisicalBrowserFlow(srv.URL)
	flow.Opener = func(bgctx context.Context, authURL string) error {
		go func() {
			time.Sleep(50 * time.Millisecond)
			cb := extractCallbackURL(authURL)
			if cb == "" {
				return
			}
			// Hit callback with NO code param to trigger the error branch.
			hitCallback(bgctx, cb)
		}()
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := flow.Login(ctx, nil)
	require.Error(t, err)
}

func TestNewInfisicalBrowserFlow_DefaultBaseURL(t *testing.T) {
	flow := NewInfisicalBrowserFlow("")
	assert.Equal(t, "https://app.infisical.com", flow.BaseURL)
}

func TestInfisicalProvider_BrowserDispatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/auth/token" {
			_ = json.NewEncoder(w).Encode(map[string]string{
				"access_token": "inf.ok", "email": "y@z",
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	flow := NewInfisicalBrowserFlow(srv.URL)
	flow.Opener = func(bgctx context.Context, authURL string) error {
		go func() {
			time.Sleep(30 * time.Millisecond)
			cb := extractCallbackURL(authURL)
			if cb != "" {
				hitCallback(bgctx, cb+"?code=xyz")
			}
		}()
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cred, err := flow.Login(ctx, nil)
	require.NoError(t, err)
	assert.Equal(t, "inf.ok", cred.Token)
}

// hitCallback issues a GET to the given URL with a context-bound request so
// lint (noctx) stays happy. Test-only helper.
func hitCallback(ctx context.Context, target string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, http.NoBody)
	if err != nil {
		return
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
}

// extractCallbackURL parses callback=... out of the skret auth URL.
func extractCallbackURL(authURL string) string {
	u, err := url.Parse(authURL)
	if err != nil {
		return ""
	}
	return u.Query().Get("callback")
}

func TestNewInfisicalProvider_Env(t *testing.T) {
	t.Setenv("INFISICAL_API_URL", "https://custom.infisical.com")
	p := NewInfisicalProvider()
	assert.Equal(t, "https://custom.infisical.com", p.baseURL)
}

func TestInfisicalProvider_LoginToken_Env(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer env-tok", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"user":{"email":"env@example.com"}}`))
	}))
	defer srv.Close()

	t.Setenv("INFISICAL_TOKEN", "env-tok")
	p := &InfisicalProvider{baseURL: srv.URL}
	cred, err := p.Login(context.Background(), "token", map[string]string{})
	require.NoError(t, err)
	assert.Equal(t, "env-tok", cred.Token)
	assert.Equal(t, "env@example.com", cred.Metadata["email"])
}
