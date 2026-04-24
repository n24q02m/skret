package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	ssooidctypes "github.com/aws/aws-sdk-go-v2/service/ssooidc/types"
)

// SSOOIDCClient is the subset of ssooidc used by the SSO login flow.
type SSOOIDCClient interface {
	RegisterClient(ctx context.Context, in *ssooidc.RegisterClientInput, opts ...func(*ssooidc.Options)) (*ssooidc.RegisterClientOutput, error)
	StartDeviceAuthorization(ctx context.Context, in *ssooidc.StartDeviceAuthorizationInput, opts ...func(*ssooidc.Options)) (*ssooidc.StartDeviceAuthorizationOutput, error)
	CreateToken(ctx context.Context, in *ssooidc.CreateTokenInput, opts ...func(*ssooidc.Options)) (*ssooidc.CreateTokenOutput, error)
}

// AWSSSOFlow performs the AWS SSO device-authorization flow.
type AWSSSOFlow struct {
	client SSOOIDCClient
	Opener func(ctx context.Context, authURL string) error
}

// NewAWSSSOFlow creates an AWS SSO flow backed by the given ssooidc client.
// Opener defaults to OpenBrowser; tests override it to avoid launching a real
// browser.
func NewAWSSSOFlow(client SSOOIDCClient) *AWSSSOFlow {
	return &AWSSSOFlow{client: client, Opener: OpenBrowser}
}

// Login registers the client, starts device auth, prints the verification URI,
// opens the browser best-effort, and polls CreateToken until the user authorizes.
// opts must contain "start_url" and "region".
func (f *AWSSSOFlow) Login(ctx context.Context, opts map[string]string) (*Credential, error) {
	startURL := opts["start_url"]
	if startURL == "" {
		return nil, fmt.Errorf("aws sso: start_url required")
	}

	reg, err := f.client.RegisterClient(ctx, &ssooidc.RegisterClientInput{
		ClientName: aws.String("skret-cli"),
		ClientType: aws.String("public"),
	})
	if err != nil {
		return nil, fmt.Errorf("aws sso: register client: %w", err)
	}

	dev, err := f.client.StartDeviceAuthorization(ctx, &ssooidc.StartDeviceAuthorizationInput{
		ClientId:     reg.ClientId,
		ClientSecret: reg.ClientSecret,
		StartUrl:     aws.String(startURL),
	})
	if err != nil {
		return nil, fmt.Errorf("aws sso: start device auth: %w", err)
	}

	fmt.Fprintf(ctxOut(ctx), "Open %s and enter code %s\n",
		aws.ToString(dev.VerificationUri), aws.ToString(dev.UserCode))
	_ = f.Opener(ctx, aws.ToString(dev.VerificationUriComplete))

	interval := time.Duration(dev.Interval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}
	deadline := time.Now().Add(time.Duration(dev.ExpiresIn) * time.Second)

	for time.Now().Before(deadline) {
		tok, err := f.client.CreateToken(ctx, &ssooidc.CreateTokenInput{
			ClientId:     reg.ClientId,
			ClientSecret: reg.ClientSecret,
			GrantType:    aws.String("urn:ietf:params:oauth:grant-type:device_code"),
			DeviceCode:   dev.DeviceCode,
		})
		if err == nil {
			return &Credential{
				Method:    "sso",
				Token:     aws.ToString(tok.AccessToken),
				ExpiresAt: time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second),
				Metadata: map[string]string{
					"start_url": startURL,
					"region":    opts["region"],
				},
			}, nil
		}
		var pending *ssooidctypes.AuthorizationPendingException
		var slow *ssooidctypes.SlowDownException
		if errors.As(err, &pending) || errors.As(err, &slow) {
			if errors.As(err, &slow) {
				interval += 5 * time.Second
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(interval):
				continue
			}
		}
		return nil, fmt.Errorf("aws sso: create token: %w", err)
	}

	return nil, fmt.Errorf("aws sso: device authorization timed out")
}
