package auth

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	ssooidctypes "github.com/aws/aws-sdk-go-v2/service/ssooidc/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeOIDC is a minimal stub implementing SSOOIDCClient.
type fakeOIDC struct {
	registered bool
	pollCalls  int
}

func (f *fakeOIDC) RegisterClient(_ context.Context, _ *ssooidc.RegisterClientInput, _ ...func(*ssooidc.Options)) (*ssooidc.RegisterClientOutput, error) {
	f.registered = true
	return &ssooidc.RegisterClientOutput{
		ClientId:     aws.String("client-id"),
		ClientSecret: aws.String("client-secret"),
	}, nil
}

func (f *fakeOIDC) StartDeviceAuthorization(_ context.Context, _ *ssooidc.StartDeviceAuthorizationInput, _ ...func(*ssooidc.Options)) (*ssooidc.StartDeviceAuthorizationOutput, error) {
	return &ssooidc.StartDeviceAuthorizationOutput{
		DeviceCode:              aws.String("device-x"),
		UserCode:                aws.String("ABCD-1234"),
		VerificationUri:         aws.String("https://device.sso.aws/"),
		VerificationUriComplete: aws.String("https://device.sso.aws/?user_code=ABCD-1234"),
		ExpiresIn:               600,
		Interval:                1,
	}, nil
}

func (f *fakeOIDC) CreateToken(_ context.Context, _ *ssooidc.CreateTokenInput, _ ...func(*ssooidc.Options)) (*ssooidc.CreateTokenOutput, error) {
	f.pollCalls++
	if f.pollCalls < 2 {
		return nil, &ssooidctypes.AuthorizationPendingException{}
	}
	return &ssooidc.CreateTokenOutput{
		AccessToken: aws.String("sso-access-token"),
		ExpiresIn:   3600,
	}, nil
}

func TestAWSSSOFlow_Success(t *testing.T) {
	fake := &fakeOIDC{}
	flow := NewAWSSSOFlow(fake)
	cred, err := flow.Login(context.Background(), map[string]string{
		"start_url": "https://example.awsapps.com/start",
		"region":    "ap-southeast-1",
	})
	require.NoError(t, err)
	assert.Equal(t, "sso-access-token", cred.Token)
	assert.Equal(t, "sso", cred.Method)
	assert.True(t, time.Now().Before(cred.ExpiresAt))
	assert.True(t, fake.registered)
	assert.GreaterOrEqual(t, fake.pollCalls, 2)
	assert.Equal(t, "https://example.awsapps.com/start", cred.Metadata["start_url"])
	assert.Equal(t, "ap-southeast-1", cred.Metadata["region"])
}

func TestAWSSSOFlow_MissingStartURL(t *testing.T) {
	flow := NewAWSSSOFlow(&fakeOIDC{})
	_, err := flow.Login(context.Background(), map[string]string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "start_url required")
}

func TestAWSSSOFlow_ContextCancelled(t *testing.T) {
	// fakeOIDC that always returns pending
	fake := &fakeOIDC{pollCalls: -100} // Will never reach 2
	flow := NewAWSSSOFlow(fake)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := flow.Login(ctx, map[string]string{
		"start_url": "https://example.awsapps.com/start",
	})
	assert.Error(t, err)
}

// fakeOIDCRegisterFail fails on RegisterClient.
type fakeOIDCRegisterFail struct{}

func (f *fakeOIDCRegisterFail) RegisterClient(_ context.Context, _ *ssooidc.RegisterClientInput, _ ...func(*ssooidc.Options)) (*ssooidc.RegisterClientOutput, error) {
	return nil, assert.AnError
}

func (f *fakeOIDCRegisterFail) StartDeviceAuthorization(_ context.Context, _ *ssooidc.StartDeviceAuthorizationInput, _ ...func(*ssooidc.Options)) (*ssooidc.StartDeviceAuthorizationOutput, error) {
	return nil, nil
}

func (f *fakeOIDCRegisterFail) CreateToken(_ context.Context, _ *ssooidc.CreateTokenInput, _ ...func(*ssooidc.Options)) (*ssooidc.CreateTokenOutput, error) {
	return nil, nil
}

func TestAWSSSOFlow_RegisterFails(t *testing.T) {
	flow := NewAWSSSOFlow(&fakeOIDCRegisterFail{})
	_, err := flow.Login(context.Background(), map[string]string{
		"start_url": "https://example.awsapps.com/start",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "register client")
}

// fakeOIDCDeviceFail fails on StartDeviceAuthorization.
type fakeOIDCDeviceFail struct{}

func (f *fakeOIDCDeviceFail) RegisterClient(_ context.Context, _ *ssooidc.RegisterClientInput, _ ...func(*ssooidc.Options)) (*ssooidc.RegisterClientOutput, error) {
	return &ssooidc.RegisterClientOutput{
		ClientId:     aws.String("id"),
		ClientSecret: aws.String("secret"),
	}, nil
}

func (f *fakeOIDCDeviceFail) StartDeviceAuthorization(_ context.Context, _ *ssooidc.StartDeviceAuthorizationInput, _ ...func(*ssooidc.Options)) (*ssooidc.StartDeviceAuthorizationOutput, error) {
	return nil, assert.AnError
}

func (f *fakeOIDCDeviceFail) CreateToken(_ context.Context, _ *ssooidc.CreateTokenInput, _ ...func(*ssooidc.Options)) (*ssooidc.CreateTokenOutput, error) {
	return nil, nil
}

func TestAWSSSOFlow_DeviceAuthFails(t *testing.T) {
	flow := NewAWSSSOFlow(&fakeOIDCDeviceFail{})
	_, err := flow.Login(context.Background(), map[string]string{
		"start_url": "https://example.awsapps.com/start",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "start device auth")
}

// --- AWS Provider Tests ---

func TestAWSProvider_Methods(t *testing.T) {
	p := NewAWSProvider()
	assert.Equal(t, "aws", p.Name())
	methods := p.Methods()
	assert.Len(t, methods, 2)
	assert.Equal(t, "sso", methods[0].Name)
	assert.Equal(t, "profile", methods[1].Name)
}

func TestAWSProvider_LoginProfile(t *testing.T) {
	p := NewAWSProvider()
	cred, err := p.Login(context.Background(), "profile", map[string]string{"profile": "my-profile"})
	require.NoError(t, err)
	assert.Equal(t, "profile", cred.Method)
	assert.Equal(t, "my-profile", cred.Metadata["profile"])
}

func TestAWSProvider_LoginProfileDefault(t *testing.T) {
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

	cred, err := p.Login(context.Background(), "sso", map[string]string{
		"start_url": "https://test.awsapps.com/start",
		"region":    "us-east-1",
	})
	require.NoError(t, err)
	assert.Equal(t, "sso", cred.Method)
	assert.Equal(t, "sso-access-token", cred.Token)
}
