package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Infisical universal-auth error paths ---

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

// --- Infisical browser error paths ---

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
			u, _ := url.Parse(authURL)
			state := u.Query().Get("state")
			hitCallback(bgctx, cb+"?code=c&state="+state)
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
			u, _ := url.Parse(authURL)
			state := u.Query().Get("state")
			hitCallback(bgctx, cb+"?state="+state)
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

// --- AWS profile error paths ---

func TestAWSProfileFlow_EmptyProfileUsesDefault(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".aws"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".aws", "config"),
		[]byte("[default]\nregion = us-east-1\n"), 0o600))
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)

	flow := NewAWSProfileFlow()
	cred, err := flow.Login(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, "default", cred.Metadata["profile"])
}

// --- AWS Keys missing AKID ---

func TestAWSKeysFlow_MissingAccessKeyID(t *testing.T) {
	in := strings.NewReader("\n")
	flow := NewAWSKeysFlow(in)
	_, err := flow.Login(context.Background(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "access key id")
}

// --- AWS Provider dispatch sso path (in-process mock) ---

func TestAWSProvider_Login_SSODispatch(t *testing.T) {
	p := NewAWSProvider()
	// Preload ssoFlow with a fake OIDC client so Login("sso", ...) dispatches
	// to it without trying to call awsconfig.LoadDefaultConfig.
	p.ssoFlow = NewAWSSSOFlow(&fakeOIDC{})
	p.ssoFlow.Opener = func(context.Context, string) error { return nil }
	cred, err := p.Login(context.Background(), "sso", map[string]string{
		"start_url":  "https://test.awsapps.com/start",
		"region":     "us-east-1",
		"account_id": "111122223333",
		"role_name":  "SkretRole",
	})
	require.NoError(t, err)
	assert.Equal(t, "sso", cred.Method)
}

// TestAWSProvider_Login_AssumeRoleMissingArn exercises the assume-role
// dispatch path in aws_provider.Login. With no role_arn opt the AWSAssumeFlow
// short-circuits with a validation error before hitting STS, so this test
// covers the dispatch branch without needing network or real AWS creds.
func TestAWSProvider_Login_AssumeRoleMissingArn(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIA-DUMMY")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "dummy-secret")
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")

	p := NewAWSProvider()
	_, err := p.Login(context.Background(), "assume-role", map[string]string{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "role_arn")
}

// --- Prompt edge coverage ---

func TestConfirm_No(t *testing.T) {
	var out strings.Builder
	ok := Confirm(strings.NewReader("n\n"), &out, "proceed?")
	assert.False(t, ok)
}

func TestConfirm_EmptyDefaultsYes(t *testing.T) {
	var out strings.Builder
	ok := Confirm(strings.NewReader("\n"), &out, "proceed?")
	assert.True(t, ok)
}

// --- Infisical provider-level dispatch success paths ---

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
				u, _ := url.Parse(authURL)
				state := u.Query().Get("state")
				hitCallback(bgctx, cb+"?code=xyz&state="+state)
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

// --- Store edge ---

func TestNewStoreWithPath_CustomPath(t *testing.T) {
	s := NewStoreWithPath("/tmp/x.yaml")
	fb, ok := s.b.(*fileBackend)
	require.True(t, ok)
	assert.Contains(t, fb.path, "x.yaml")
}

func TestConfirm_ReadErr(t *testing.T) {
	var out strings.Builder
	// Empty reader returns io.EOF immediately with empty line → treated as false.
	ok := Confirm(strings.NewReader(""), &out, "proceed?")
	assert.False(t, ok)
}

func TestSelectMethod_InvalidChoice(t *testing.T) {
	var out strings.Builder
	methods := []Method{{Name: "a", Description: "a"}, {Name: "b", Description: "b"}}
	_, err := SelectMethod(strings.NewReader("999\n"), &out, methods)
	require.Error(t, err)
}

func TestSelectMethod_Valid(t *testing.T) {
	var out strings.Builder
	methods := []Method{{Name: "a", Description: "a"}, {Name: "b"}}
	m, err := SelectMethod(strings.NewReader("2\n"), &out, methods)
	require.NoError(t, err)
	assert.Equal(t, "b", m.Name)
}
