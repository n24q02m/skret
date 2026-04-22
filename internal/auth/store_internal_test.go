package auth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStore_Write_WithNewDir(t *testing.T) {
	dir := t.TempDir()
	s := &Store{path: filepath.Join(dir, "deep", "nested", "creds.yaml")}
	err := s.Save(&Credential{Provider: "test", Token: "x"})
	require.NoError(t, err)

	_, err = os.Stat(filepath.Join(dir, "deep", "nested", "creds.yaml"))
	require.NoError(t, err)
}

func TestStore_Write_DirectCall(t *testing.T) {
	dir := t.TempDir()
	s := &Store{path: filepath.Join(dir, "creds.yaml")}

	f := &storeFile{
		Version: "1",
		Providers: map[string]*Credential{
			"aws":     {Method: "sso", Token: "aws-tok"},
			"doppler": {Method: "oauth", Token: "dp-tok"},
		},
	}
	require.NoError(t, s.write(f))

	loaded, err := s.read()
	require.NoError(t, err)
	assert.Len(t, loaded.Providers, 2)
	assert.Equal(t, "aws-tok", loaded.Providers["aws"].Token)
}

func TestStore_Write_RenameError(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	require.NoError(t, os.Mkdir(target, 0o700))
	s := &Store{path: target}
	f := &storeFile{Version: "1", Providers: map[string]*Credential{}}
	err := s.write(f)
	assert.Error(t, err)
}

func TestStore_Read_NonExistent(t *testing.T) {
	s := &Store{path: "/nonexistent/path/that/fails"}
	f, err := s.read()
	require.NoError(t, err)
	assert.NotNil(t, f)
	assert.Empty(t, f.Providers)
}

func TestStore_Read_ValidYAMLMissingVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.yaml")
	require.NoError(t, os.WriteFile(path, []byte("providers:\n  aws:\n    token: tok"), 0o600))

	s := &Store{path: path}
	f, err := s.read()
	require.NoError(t, err)
	assert.Equal(t, "1", f.Version)
	assert.Equal(t, "tok", f.Providers["aws"].Token)
}

func TestStore_Read_ValidYAMLNilProviders(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.yaml")
	require.NoError(t, os.WriteFile(path, []byte("version: \"1\"\n"), 0o600))

	s := &Store{path: path}
	f, err := s.read()
	require.NoError(t, err)
	assert.NotNil(t, f.Providers)
	assert.Empty(t, f.Providers)
}

func TestStore_Save_ReadError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.yaml")
	require.NoError(t, os.WriteFile(path, []byte("{{{bad yaml"), 0o600))

	s := &Store{path: path}
	err := s.Save(&Credential{Provider: "test", Token: "x"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "parse")
}

func TestStore_Delete_ReadError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.yaml")
	require.NoError(t, os.WriteFile(path, []byte("{{{bad yaml"), 0o600))

	s := &Store{path: path}
	err := s.Delete("test")
	assert.Error(t, err)
}

func TestStore_List_ReadError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.yaml")
	require.NoError(t, os.WriteFile(path, []byte("{{{bad yaml"), 0o600))

	s := &Store{path: path}
	_, err := s.List()
	assert.Error(t, err)
}

func TestStore_Load_ReadError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.yaml")
	require.NoError(t, os.WriteFile(path, []byte("{{{bad yaml"), 0o600))

	s := &Store{path: path}
	_, err := s.Load("test")
	assert.Error(t, err)
}

func TestIsInteractiveStdin_InTest(t *testing.T) {
	result := IsInteractiveStdin()
	_ = result // Just verify no panic
}

func TestResolve_ExpiredCredential(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	s := NewStore()
	require.NoError(t, s.Save(&Credential{
		Provider:  "doppler",
		Token:     "expired-tok",
		ExpiresAt: time.Now().Add(-time.Hour),
	}))

	_, err := Resolve(context.Background(), "doppler")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestResolve_LoadError(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	require.NoError(t, os.MkdirAll(filepath.Join(home, ".skret"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(home, ".skret", "credentials.yaml"), []byte("{{{bad"), 0o600))

	_, err := Resolve(context.Background(), "doppler")
	assert.Error(t, err)
}

func TestOpenBrowser_CancelledCtx(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = OpenBrowser(ctx, "https://example.com")
}

func TestWithAutoAuth_SuccessPassthrough(t *testing.T) {
	calls := 0
	err := WithAutoAuth(context.Background(), "test", func() error {
		calls++
		return nil
	})
	assert.NoError(t, err)
	assert.Equal(t, 1, calls)
}

func TestWithAutoAuth_NonAuthErrorPassthrough(t *testing.T) {
	want := errors.New("disk full")
	err := WithAutoAuth(context.Background(), "test", func() error {
		return want
	})
	assert.ErrorIs(t, err, want)
}

func TestIsAuthError_Comprehensive(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		expect bool
	}{
		{"nil", nil, false},
		{"random", errors.New("random error"), false},
		{"401", errors.New("API returned 401"), true},
		{"403", errors.New("got 403 forbidden"), true},
		{"unauthorized", errors.New("UnauthorizedException"), true},
		{"invalid grant", errors.New("InvalidGrantException"), true},
		{"expired token", errors.New("ExpiredTokenException"), true},
		{"cred missing", errors.New("credentials missing"), true},
		{"resolve creds", errors.New("could not resolve credentials"), true},
		{"not found", ErrCredentialNotFound, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expect, IsAuthError(tt.err))
		})
	}
}

func TestNewStore_Fallback(t *testing.T) {
	s := NewStore()
	assert.NotNil(t, s)
	assert.NotEmpty(t, s.path)
}

func TestCtxOut_Returns(t *testing.T) {
	w := ctxOut(context.Background())
	assert.NotNil(t, w)
}
