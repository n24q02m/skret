package aws

import (
	"context"
	"fmt"
	"time"

	awslib "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/n24q02m/skret/internal/auth"
)

// ssoTokenRefresher mints a new SSO access token from a refresh token (no
// browser, no device flow). Satisfied by *ssooidc.Client.
type ssoTokenRefresher interface {
	CreateToken(ctx context.Context, in *ssooidc.CreateTokenInput, optFns ...func(*ssooidc.Options)) (*ssooidc.CreateTokenOutput, error)
}

// ssoRoleFetcher exchanges an SSO access token for temporary IAM role
// credentials. Satisfied by *sso.Client.
type ssoRoleFetcher interface {
	GetRoleCredentials(ctx context.Context, in *sso.GetRoleCredentialsInput, optFns ...func(*sso.Options)) (*sso.GetRoleCredentialsOutput, error)
}

// Factory + persistence hooks — overridable in tests (no network, no browser).
var (
	newSSORefresher = func(region string) (ssoTokenRefresher, error) {
		cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(region))
		if err != nil {
			return nil, err
		}
		return ssooidc.NewFromConfig(cfg), nil
	}
	newSSORoleFetcher = func(region string) (ssoRoleFetcher, error) {
		cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(region))
		if err != nil {
			return nil, err
		}
		return sso.NewFromConfig(cfg), nil
	}
	ssoStoreSave = func(c *auth.Credential) error { return auth.NewStore().Save(c) }
)

// ssoProvider is an aws.CredentialsProvider that keeps an IAM Identity Center
// session alive silently: when the cached SSO access token is near expiry it
// refreshes via the OIDC refresh token (no browser), persists the rotated
// token, then exchanges it for temporary IAM role credentials. This is what
// makes `skret auth login aws --method sso` last the whole SSO session
// (admin-configurable up to 90 days) without re-authenticating.
type ssoProvider struct{ cred *auth.Credential }

func (p *ssoProvider) region() string {
	if r := p.cred.Metadata["region"]; r != "" {
		return r
	}
	return "us-east-1"
}

func (p *ssoProvider) refreshIfNeeded(ctx context.Context) error {
	if p.cred.Token != "" && time.Until(p.cred.ExpiresAt) > 60*time.Second {
		return nil
	}
	r, err := newSSORefresher(p.region())
	if err != nil {
		return fmt.Errorf("aws sso: build refresher: %w", err)
	}
	m := p.cred.Metadata
	out, err := r.CreateToken(ctx, &ssooidc.CreateTokenInput{
		ClientId:     awslib.String(m["client_id"]),
		ClientSecret: awslib.String(m["client_secret"]),
		GrantType:    awslib.String("refresh_token"),
		RefreshToken: awslib.String(m["refresh_token"]),
	})
	if err != nil {
		return fmt.Errorf("aws sso refresh: %w", err)
	}
	p.cred.Token = awslib.ToString(out.AccessToken)
	p.cred.ExpiresAt = time.Now().Add(time.Duration(out.ExpiresIn) * time.Second)
	if rt := awslib.ToString(out.RefreshToken); rt != "" {
		p.cred.Metadata["refresh_token"] = rt
	}
	if p.cred.Provider == "" {
		p.cred.Provider = "aws"
	}
	_ = ssoStoreSave(p.cred)
	return nil
}

func (p *ssoProvider) Retrieve(ctx context.Context) (awslib.Credentials, error) {
	if err := p.refreshIfNeeded(ctx); err != nil {
		return awslib.Credentials{}, err
	}
	rf, err := newSSORoleFetcher(p.region())
	if err != nil {
		return awslib.Credentials{}, fmt.Errorf("aws sso: build role fetcher: %w", err)
	}
	m := p.cred.Metadata
	out, err := rf.GetRoleCredentials(ctx, &sso.GetRoleCredentialsInput{
		AccessToken: awslib.String(p.cred.Token),
		AccountId:   awslib.String(m["account_id"]),
		RoleName:    awslib.String(m["role_name"]),
	})
	if err != nil {
		return awslib.Credentials{}, fmt.Errorf("aws sso get role credentials: %w", err)
	}
	rc := out.RoleCredentials
	return awslib.Credentials{
		AccessKeyID:     awslib.ToString(rc.AccessKeyId),
		SecretAccessKey: awslib.ToString(rc.SecretAccessKey),
		SessionToken:    awslib.ToString(rc.SessionToken),
		Source:          "skret-sso",
		CanExpire:       true,
		Expires:         time.UnixMilli(rc.Expiration).UTC(),
	}, nil
}
