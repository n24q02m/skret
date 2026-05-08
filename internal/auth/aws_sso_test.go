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
	flow.Opener = func(context.Context, string) error { return nil }
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
	flow.Opener = func(context.Context, string) error { return nil }

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
