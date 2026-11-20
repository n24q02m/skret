package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	ssooidctypes "github.com/aws/aws-sdk-go-v2/service/ssooidc/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zalando/go-keyring"
)

// TestLogin_ProviderLoginErrorIsWrapped pins that a provider's login failure
// reaches the caller wrapped with the provider name and nothing is stored.
func TestLogin_ProviderLoginErrorIsWrapped(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	keyring.MockInit()
	sentinel := errors.New("device flow rejected")
	Register("edge-login-fails", &fakeProvider{
		name:    "edge-login-fails",
		methods: []Method{{Name: "token"}},
		loginFn: func(context.Context, string, map[string]string) (*Credential, error) {
			return nil, sentinel
		},
	})
	t.Cleanup(func() { delete(registry, "edge-login-fails") })

	err := Login(context.Background(), "edge-login-fails", nil)
	require.ErrorIs(t, err, sentinel)
	assert.Contains(t, err.Error(), "auth edge-login-fails: login:")

	_, err = NewStore().Load("edge-login-fails")
	assert.ErrorIs(t, err, ErrCredentialNotFound, "a failed login must not leave a stored credential")
}

// --- AWS bootstrap: existing inline policy handling ---

func provisionWithPolicyLookup(t *testing.T, lookup func(*iam.GetUserPolicyInput) (*iam.GetUserPolicyOutput, error)) (*fakeIAM, error) {
	t.Helper()
	iamFake := &fakeIAM{
		getUserFn: func(*iam.GetUserInput) (*iam.GetUserOutput, error) {
			return &iam.GetUserOutput{}, nil
		},
		getUserPolicyFn:   lookup,
		createAccessKeyFn: okCreateAccessKey(),
	}
	flow := &BootstrapFlow{IAM: iamFake, STS: okSTS()}
	_, err := flow.Provision(context.Background(), BootstrapOpts{
		Project: "myapp", Path: "/myapp/prod", Region: testRegion,
	})
	return iamFake, err
}

// TestProvision_MissingPolicyIsCreated pins that NoSuchEntity on the policy
// lookup means "first bootstrap": the scoped policy is written and a key is
// issued.
func TestProvision_MissingPolicyIsCreated(t *testing.T) {
	iamFake, err := provisionWithPolicyLookup(t, func(*iam.GetUserPolicyInput) (*iam.GetUserPolicyOutput, error) {
		return nil, &iamtypes.NoSuchEntityException{Message: aws.String("no such policy")}
	})
	require.NoError(t, err)
	assert.Equal(t, 1, iamFake.putPolicyCalls)
	assert.Equal(t, 1, iamFake.createAccessKeyCalls)
}

// TestProvision_PolicyLookupErrorStops pins that any other policy lookup
// failure (for example access denied) aborts before the policy is written or
// a key is issued.
func TestProvision_PolicyLookupErrorStops(t *testing.T) {
	iamFake, err := provisionWithPolicyLookup(t, func(*iam.GetUserPolicyInput) (*iam.GetUserPolicyOutput, error) {
		return nil, errors.New("AccessDenied")
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `bootstrap: get policy "skret-myapp"`)
	assert.Equal(t, 0, iamFake.putPolicyCalls)
	assert.Equal(t, 0, iamFake.createAccessKeyCalls)
}

// TestProvision_UnreadableExistingPolicyStops pins that an existing policy
// document skret cannot decode or parse is never overwritten: bootstrap
// stops with the decode/parse error instead of treating it as a match or a
// conflict.
func TestProvision_UnreadableExistingPolicyStops(t *testing.T) {
	tests := []struct {
		name     string
		document string
		want     string
	}{
		{"bad url escape", "%zz", "bootstrap: decode policy document"},
		{"not json", "%7Bnot-json", "bootstrap: parse policy document"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iamFake, err := provisionWithPolicyLookup(t, func(*iam.GetUserPolicyInput) (*iam.GetUserPolicyOutput, error) {
				return &iam.GetUserPolicyOutput{PolicyDocument: aws.String(tt.document)}, nil
			})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
			assert.Equal(t, 0, iamFake.putPolicyCalls)
			assert.Equal(t, 0, iamFake.createAccessKeyCalls)
		})
	}
}

// --- AWS SSO device flow polling ---

// scriptedOIDC is an SSOOIDCClient whose device authorization and token
// answers are set per test.
type scriptedOIDC struct {
	interval  int32
	expiresIn int32
	token     func(n int) (*ssooidc.CreateTokenOutput, error)
	calls     int
}

func (s *scriptedOIDC) RegisterClient(context.Context, *ssooidc.RegisterClientInput, ...func(*ssooidc.Options)) (*ssooidc.RegisterClientOutput, error) {
	return &ssooidc.RegisterClientOutput{
		ClientId: aws.String("client-id"), ClientSecret: aws.String("client-secret"),
	}, nil
}

func (s *scriptedOIDC) StartDeviceAuthorization(context.Context, *ssooidc.StartDeviceAuthorizationInput, ...func(*ssooidc.Options)) (*ssooidc.StartDeviceAuthorizationOutput, error) {
	return &ssooidc.StartDeviceAuthorizationOutput{
		DeviceCode:              aws.String("device-x"),
		UserCode:                aws.String("ABCD-1234"),
		VerificationUri:         aws.String("https://device.sso.aws/"),
		VerificationUriComplete: aws.String("https://device.sso.aws/?user_code=ABCD-1234"),
		ExpiresIn:               s.expiresIn,
		Interval:                s.interval,
	}, nil
}

func (s *scriptedOIDC) CreateToken(context.Context, *ssooidc.CreateTokenInput, ...func(*ssooidc.Options)) (*ssooidc.CreateTokenOutput, error) {
	s.calls++
	return s.token(s.calls)
}

func ssoFlowFor(client *scriptedOIDC) *AWSSSOFlow {
	flow := NewAWSSSOFlow(client)
	flow.Opener = func(context.Context, string) error { return nil }
	return flow
}

// TestAWSSSOFlow_ZeroIntervalStillLogsIn pins that a device authorization
// without a polling interval falls back to the default instead of failing,
// and an immediate approval returns the token.
func TestAWSSSOFlow_ZeroIntervalStillLogsIn(t *testing.T) {
	client := &scriptedOIDC{interval: 0, expiresIn: 600, token: func(int) (*ssooidc.CreateTokenOutput, error) {
		return &ssooidc.CreateTokenOutput{AccessToken: aws.String("sso-access-token"), ExpiresIn: 3600}, nil
	}}
	cred, err := ssoFlowFor(client).Login(context.Background(), ssoOpts())
	require.NoError(t, err)
	assert.Equal(t, "sso", cred.Method)
	assert.Equal(t, 1, client.calls)
}

// TestAWSSSOFlow_SlowDownHonoursCancellation pins that a SlowDown answer
// keeps polling (it is not a failure) and that cancelling while waiting
// returns the context error instead of a token or a create-token error.
func TestAWSSSOFlow_SlowDownHonoursCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := &scriptedOIDC{interval: 1, expiresIn: 600, token: func(int) (*ssooidc.CreateTokenOutput, error) {
		cancel()
		return nil, &ssooidctypes.SlowDownException{}
	}}
	_, err := ssoFlowFor(client).Login(ctx, ssoOpts())
	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, 1, client.calls)
}

// TestAWSSSOFlow_TokenErrorStops pins that a token error other than pending
// or slow-down ends the login at once with the wrapped error.
func TestAWSSSOFlow_TokenErrorStops(t *testing.T) {
	client := &scriptedOIDC{interval: 1, expiresIn: 600, token: func(int) (*ssooidc.CreateTokenOutput, error) {
		return nil, &ssooidctypes.AccessDeniedException{}
	}}
	_, err := ssoFlowFor(client).Login(context.Background(), ssoOpts())
	var denied *ssooidctypes.AccessDeniedException
	require.ErrorAs(t, err, &denied)
	assert.Contains(t, err.Error(), "aws sso: create token")
	assert.Equal(t, 1, client.calls)
}

// TestAWSSSOFlow_ExpiredDeviceCodeTimesOut pins that a device code that is
// already expired is reported as a timeout without polling for a token.
func TestAWSSSOFlow_ExpiredDeviceCodeTimesOut(t *testing.T) {
	client := &scriptedOIDC{interval: 1, expiresIn: 0, token: func(int) (*ssooidc.CreateTokenOutput, error) {
		return &ssooidc.CreateTokenOutput{AccessToken: aws.String("unused")}, nil
	}}
	_, err := ssoFlowFor(client).Login(context.Background(), ssoOpts())
	require.EqualError(t, err, "aws sso: device authorization timed out")
	assert.Equal(t, 0, client.calls)
}

// --- Keyring availability and migration ---

// TestKeyringAvailable_SetFailureMeansUnavailable pins that a keyring that
// refuses the probe write is reported unavailable, so the store falls back
// to the file backend.
func TestKeyringAvailable_SetFailureMeansUnavailable(t *testing.T) {
	keyring.MockInitWithError(errors.New("no secret service"))
	t.Cleanup(keyring.MockInit)
	assert.False(t, keyringAvailable())
}

// countingKeyring records reads and can fail writes or answer with a
// different provider set than the one written.
type countingKeyring struct {
	writeErr error
	readBack *storeFile
	reads    int
	writes   int
}

func (c *countingKeyring) read() (*storeFile, error) { c.reads++; return c.readBack, nil }
func (c *countingKeyring) write(*storeFile) error    { c.writes++; return c.writeErr }
func (c *countingKeyring) delete(string) error       { return nil }

func writeLegacyCredentials(t *testing.T) (*fileBackend, string) {
	t.Helper()
	fp := filepath.Join(t.TempDir(), "credentials.yaml")
	fb := &fileBackend{path: fp}
	require.NoError(t, fb.write(&storeFile{Version: "1", Providers: map[string]*Credential{
		"aws": {Provider: "aws", Method: "sso", Token: "t"},
	}}))
	before, err := os.ReadFile(fp)
	require.NoError(t, err)
	return fb, string(before)
}

// TestMigrate_KeyringWriteFailsLeavesSource pins that a failed keyring write
// stops the migration before any read-back. The legacy file is never
// rewritten by the migration on any path; the byte comparison guards that.
func TestMigrate_KeyringWriteFailsLeavesSource(t *testing.T) {
	fb, before := writeLegacyCredentials(t)
	kb := &countingKeyring{writeErr: errors.New("keyring locked")}

	migrateFileToKeyring(fb, kb)

	assert.Equal(t, 1, kb.writes)
	assert.Equal(t, 0, kb.reads)
	after, err := os.ReadFile(fb.path)
	require.NoError(t, err)
	assert.Equal(t, before, string(after))
}

// TestMigrate_ReadBackWithOtherProviderLeavesSource covers a read-back with
// the right provider count but a different provider name: the migration
// performs exactly one write and one read-back and the legacy file stays
// byte-identical.
func TestMigrate_ReadBackWithOtherProviderLeavesSource(t *testing.T) {
	fb, before := writeLegacyCredentials(t)
	kb := &countingKeyring{readBack: &storeFile{Version: "1", Providers: map[string]*Credential{
		"doppler": {Provider: "doppler", Method: "oauth", Token: "other"},
	}}}

	migrateFileToKeyring(fb, kb)

	assert.Equal(t, 1, kb.writes)
	assert.Equal(t, 1, kb.reads)
	after, err := os.ReadFile(fb.path)
	require.NoError(t, err)
	assert.Equal(t, before, string(after))
}

// TestFileBackendWrite_ParentIsAFile pins that the file store reports a
// mkdir error when its directory path is blocked by a regular file.
func TestFileBackendWrite_ParentIsAFile(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o600))
	fb := &fileBackend{path: filepath.Join(blocker, "credentials.yaml")}

	err := fb.write(&storeFile{Version: "1", Providers: map[string]*Credential{}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "auth store: mkdir")
}

// --- Base URL validation ---

// TestDopplerOAuthFlow_InvalidBaseURL pins that a malformed base URL fails
// before any request is sent.
func TestDopplerOAuthFlow_InvalidBaseURL(t *testing.T) {
	flow := NewDopplerOAuthFlow("http://[::1")
	_, err := flow.Login(context.Background(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "doppler oauth: build device request")
}

// TestDopplerTokenLogin_InvalidBaseURL pins that token validation against a
// malformed base URL fails with a parse error and never echoes the token.
func TestDopplerTokenLogin_InvalidBaseURL(t *testing.T) {
	p := &dopplerProvider{baseURL: "http://[::1"}
	_, err := p.loginToken(context.Background(), "service-token", map[string]string{"token": "dp.st.edge-token"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "doppler: parse base url")
	assert.NotContains(t, err.Error(), "dp.st.edge-token")
}

// TestAWSProfileLogin_NoConfigFile pins that profile login without an
// ~/.aws/config reports the missing file instead of an empty profile list.
func TestAWSProfileLogin_NoConfigFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	_, err := (&AWSProfileFlow{}).Login(context.Background(), map[string]string{"profile": "dev"})
	require.Error(t, err)
	assert.ErrorIs(t, err, os.ErrNotExist)
	assert.Contains(t, err.Error(), "aws profile:")
}

// --- Infisical browser token exchange ---

// answerInfisicalCallback plays the browser: it calls the local callback URL
// carried in authURL with a code and the expected state.
func answerInfisicalCallback(ctx context.Context, authURL string) error {
	u, err := url.Parse(authURL)
	if err != nil {
		return err
	}
	cb := u.Query().Get("callback") + "?code=browser-code&state=" + url.QueryEscape(u.Query().Get("state"))
	go func() {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, cb, http.NoBody)
		if err != nil {
			return
		}
		if resp, err := http.DefaultClient.Do(req); err == nil {
			_ = resp.Body.Close()
		}
	}()
	return nil
}

// TestInfisicalBrowserFlow_TokenExchangeTransportError pins that a token
// endpoint that drops the connection fails the login with the exchange
// error.
func TestInfisicalBrowserFlow_TokenExchangeTransportError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			_ = conn.Close()
		}
	}))
	defer srv.Close()
	flow := NewInfisicalBrowserFlow(srv.URL)
	flow.Opener = answerInfisicalCallback

	_, err := flow.Login(context.Background(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "infisical browser: token exchange")
}

// TestInfisicalBrowserFlow_TokenNotJSON pins that a 200 answer that is not a
// JSON token document fails the login instead of storing an empty token.
func TestInfisicalBrowserFlow_TokenNotJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html>not a token</html>"))
	}))
	defer srv.Close()
	flow := NewInfisicalBrowserFlow(srv.URL)
	flow.Opener = answerInfisicalCallback

	cred, err := flow.Login(context.Background(), nil)
	require.Error(t, err)
	assert.Nil(t, cred)
	assert.Contains(t, err.Error(), "infisical browser: decode token")
}
