package auth

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeProvider implements Provider for testing.
type fakeProvider struct {
	name    string
	methods []Method
	loginFn func(ctx context.Context, method string, opts map[string]string) (*Credential, error)
}

func (f *fakeProvider) Name() string                                    { return f.name }
func (f *fakeProvider) Methods() []Method                               { return f.methods }
func (f *fakeProvider) Validate(_ context.Context, _ *Credential) error { return nil }
func (f *fakeProvider) Logout(_ context.Context) error                  { return nil }

func (f *fakeProvider) Login(ctx context.Context, method string, opts map[string]string) (*Credential, error) {
	return f.loginFn(ctx, method, opts)
}

func TestLogin_RegisteredProvider(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	Register("test-provider", &fakeProvider{
		name:    "test-provider",
		methods: []Method{{Name: "token"}},
		loginFn: func(_ context.Context, _ string, _ map[string]string) (*Credential, error) {
			return &Credential{
				Method: "token",
				Token:  "test-token-123",
			}, nil
		},
	})
	defer delete(registry, "test-provider")

	err := Login(context.Background(), "test-provider", nil)
	require.NoError(t, err)

	// Verify credential was saved
	s := NewStore()
	cred, err := s.Load("test-provider")
	require.NoError(t, err)
	assert.Equal(t, "test-token-123", cred.Token)
	assert.Equal(t, "test-provider", cred.Provider)
}

func TestLogin_WithMethod(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	var capturedMethod string
	Register("test-method", &fakeProvider{
		name:    "test-method",
		methods: []Method{{Name: "sso"}, {Name: "key"}},
		loginFn: func(_ context.Context, method string, _ map[string]string) (*Credential, error) {
			capturedMethod = method
			return &Credential{Method: method, Token: "tok"}, nil
		},
	})
	defer delete(registry, "test-method")

	err := Login(context.Background(), "test-method", map[string]string{"method": "sso"})
	require.NoError(t, err)
	assert.Equal(t, "sso", capturedMethod)
}

func TestResolve_ValidCredential(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	s := NewStore()
	require.NoError(t, s.Save(&Credential{
		Provider: "doppler",
		Token:    "valid-tok",
	}))

	cred, err := Resolve(context.Background(), "doppler")
	require.NoError(t, err)
	assert.Equal(t, "valid-tok", cred.Token)
}

func TestCtxOut(t *testing.T) {
	w := ctxOut(context.Background())
	assert.NotNil(t, w)
}

func TestWithAutoAuthIO_Interactive_UserDeclines(t *testing.T) {
	var stderr bytes.Buffer
	stdin := strings.NewReader("n\n")
	origErr := ErrCredentialNotFound

	err := withAutoAuthIO(context.Background(), "doppler", func() error {
		return origErr
	}, stdin, &stderr, false)

	assert.ErrorIs(t, err, origErr)
	assert.Contains(t, stderr.String(), "credentials missing or expired")
}

func TestWithAutoAuthIO_Interactive_LoginFails(t *testing.T) {
	var stderr bytes.Buffer
	stdin := strings.NewReader("y\n")

	// No provider registered -> Login will fail
	err := withAutoAuthIO(context.Background(), "no-such-provider", func() error {
		return ErrCredentialNotFound
	}, stdin, &stderr, false)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "auth no-such-provider")
}

func TestWithAutoAuthIO_Interactive_LoginSuccessRetry(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	Register("retry-test", &fakeProvider{
		name:    "retry-test",
		methods: []Method{{Name: "token"}},
		loginFn: func(_ context.Context, _ string, _ map[string]string) (*Credential, error) {
			return &Credential{Method: "token", Token: "new-tok"}, nil
		},
	})
	defer delete(registry, "retry-test")

	var stderr bytes.Buffer
	stdin := strings.NewReader("y\n")
	calls := 0

	err := withAutoAuthIO(context.Background(), "retry-test", func() error {
		calls++
		if calls == 1 {
			return ErrCredentialNotFound
		}
		return nil // success on retry
	}, stdin, &stderr, false)

	require.NoError(t, err)
	assert.Equal(t, 2, calls)
}

func TestWithAutoAuthIO_NonInteractive(t *testing.T) {
	var stderr bytes.Buffer
	err := withAutoAuthIO(context.Background(), "doppler", func() error {
		return ErrCredentialNotFound
	}, nil, &stderr, true)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "skret auth doppler")
}

func TestIsNonInteractive(t *testing.T) {
	// Just verify it doesn't panic; value depends on test runner
	_ = isNonInteractive()
}
