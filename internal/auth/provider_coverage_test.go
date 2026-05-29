package auth

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
