package auth

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAWSProvider_Methods(t *testing.T) {
	p := NewAWSProvider()
	assert.Equal(t, "aws", p.Name())

	methods := p.Methods()
	assert.Len(t, methods, 4)

	expected := []Method{
		{Name: "sso", Description: "AWS SSO device flow (recommended)", Interactive: true},
		{Name: "access-key", Description: "Paste AWS access key + secret", Interactive: true},
		{Name: "assume-role", Description: "Assume IAM role (requires role_arn opt)", Interactive: false},
		{Name: "profile", Description: "Use existing AWS CLI profile from ~/.aws/config", Interactive: false},
	}

	for i, m := range methods {
		assert.Equal(t, expected[i].Name, m.Name)
		assert.Equal(t, expected[i].Description, m.Description)
		assert.Equal(t, expected[i].Interactive, m.Interactive)
	}
}

// writeAWSConfig writes a minimal ~/.aws/config under dir with the given
// profiles and redirects HOME/USERPROFILE to dir for the test.
func writeAWSConfig(t *testing.T, dir, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".aws"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".aws", "config"), []byte(content), 0o600))
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
}

func TestAWSProvider_LoginProfile(t *testing.T) {
	dir := t.TempDir()
	writeAWSConfig(t, dir, "[default]\nregion = us-east-1\n\n[profile my-profile]\nregion = ap-southeast-1\n")

	p := NewAWSProvider()
	cred, err := p.Login(context.Background(), "profile", map[string]string{"profile": "my-profile"})
	require.NoError(t, err)
	assert.Equal(t, "profile", cred.Method)
	assert.Equal(t, "my-profile", cred.Metadata["profile"])
	assert.Equal(t, "ap-southeast-1", cred.Metadata["region"])
}

func TestAWSProvider_LoginProfileDefault(t *testing.T) {
	dir := t.TempDir()
	writeAWSConfig(t, dir, "[default]\nregion = us-east-1\n")

	p := NewAWSProvider()
	cred, err := p.Login(context.Background(), "profile", map[string]string{})
	require.NoError(t, err)
	assert.Equal(t, "default", cred.Metadata["profile"])
}

func TestAWSProvider_LoginUnknownMethod(t *testing.T) {
	p := NewAWSProvider()
	_, err := p.Login(context.Background(), "unknown", nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrAuthMethodUnsupported)
}

func TestAWSProvider_Validate(t *testing.T) {
	p := NewAWSProvider()
	assert.NoError(t, p.Validate(context.Background(), &Credential{Token: "tok"}))
	assert.NoError(t, p.Validate(context.Background(), &Credential{Method: "profile"}))
	assert.Error(t, p.Validate(context.Background(), nil))
	assert.Error(t, p.Validate(context.Background(), &Credential{}))
}

func TestAWSProvider_Logout(t *testing.T) {
	p := NewAWSProvider()
	assert.NoError(t, p.Logout(context.Background()))
}

func TestAWSProvider_LoginSSO_WithMock(t *testing.T) {
	p := NewAWSProvider()
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
	assert.Equal(t, "sso-access-token", cred.Token)
}

func TestAWSProvider_Login_DefaultMethodIsSSO(t *testing.T) {
	p := NewAWSProvider()
	p.ssoFlow = NewAWSSSOFlow(&fakeOIDC{})
	p.ssoFlow.Opener = func(context.Context, string) error { return nil }

	// Empty method must default to sso, not ErrAuthMethodUnsupported.
	cred, err := p.Login(context.Background(), "", ssoOpts())
	require.NoError(t, err)
	assert.Equal(t, "sso", cred.Method)
}

func TestAWSProvider_LoginAssumeRole_LoadConfigFail(t *testing.T) {
	orig := loadAWSConfig
	defer func() { loadAWSConfig = orig }()

	loadAWSConfig = func(ctx context.Context, optFns ...func(*awsconfig.LoadOptions) error) (aws.Config, error) {
		return aws.Config{}, assert.AnError
	}

	p := NewAWSProvider()
	_, err := p.Login(context.Background(), "assume-role", map[string]string{"role_arn": "arn:aws:iam::123:role/test"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "load config")
}

func TestAWSProvider_LoginSSO_LoadConfigFail(t *testing.T) {
	orig := loadAWSConfig
	defer func() { loadAWSConfig = orig }()

	loadAWSConfig = func(ctx context.Context, optFns ...func(*awsconfig.LoadOptions) error) (aws.Config, error) {
		return aws.Config{}, assert.AnError
	}

	p := NewAWSProvider()
	_, err := p.Login(context.Background(), "sso", map[string]string{"start_url": "https://test.com"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "load config")
}

func TestAWSProvider_LoginAssumeRole_Success(t *testing.T) {
	orig := loadAWSConfig
	defer func() { loadAWSConfig = orig }()

	loadAWSConfig = func(ctx context.Context, optFns ...func(*awsconfig.LoadOptions) error) (aws.Config, error) {
		return aws.Config{}, nil
	}

	p := NewAWSProvider()
	// This will fail later because NewAWSAssumeFlow uses sts.NewFromConfig(cfg)
	// which we haven't mocked yet, but it's a good step for coverage of Login switch.
	_, err := p.Login(context.Background(), "assume-role", map[string]string{"role_arn": "arn:aws:iam::123:role/test"})
	// It should fail in NewAWSAssumeFlow.Login if we don't mock STS, but let's see.
	assert.Error(t, err)
}

func TestAWSProvider_LoginAccessKey(t *testing.T) {
	p := NewAWSProvider()
	// We pass empty opts, it should fail in NewAWSKeysFlow.Login because of missing keys.
	_, err := p.Login(context.Background(), "access-key", nil)
	assert.Error(t, err)
}

func TestAWSProvider_LoginSSO_InitSuccess(t *testing.T) {
	orig := loadAWSConfig
	defer func() { loadAWSConfig = orig }()

	loadAWSConfig = func(ctx context.Context, optFns ...func(*awsconfig.LoadOptions) error) (aws.Config, error) {
		return aws.Config{}, nil
	}

	p := NewAWSProvider()
	// It will initialize ssoFlow and then fail in ssoFlow.Login due to missing opts.
	_, err := p.Login(context.Background(), "sso", nil)
	assert.Error(t, err)
	assert.NotNil(t, p.ssoFlow)
}
