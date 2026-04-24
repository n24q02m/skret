package auth

import (
	"context"
	"fmt"
	"os"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// AWSProvider implements the auth.Provider interface for AWS.
type AWSProvider struct {
	ssoFlow *AWSSSOFlow
}

// NewAWSProvider creates the AWS auth provider.
func NewAWSProvider() *AWSProvider {
	return &AWSProvider{}
}

func (p *AWSProvider) Name() string { return "aws" }

func (p *AWSProvider) Methods() []Method {
	return []Method{
		{Name: "sso", Description: "AWS SSO device flow (recommended)", Interactive: true},
		{Name: "access-key", Description: "Paste AWS access key + secret", Interactive: true},
		{Name: "assume-role", Description: "Assume IAM role (requires role_arn opt)", Interactive: false},
		{Name: "profile", Description: "Use existing AWS CLI profile from ~/.aws/config", Interactive: false},
	}
}

func (p *AWSProvider) Login(ctx context.Context, method string, opts map[string]string) (*Credential, error) {
	switch method {
	case "sso":
		return p.loginSSO(ctx, opts)
	case "access-key":
		return NewAWSKeysFlow(os.Stdin).Login(ctx, opts)
	case "assume-role":
		cfg, err := awsconfig.LoadDefaultConfig(ctx)
		if err != nil {
			return nil, fmt.Errorf("aws: load config: %w", err)
		}
		return NewAWSAssumeFlow(sts.NewFromConfig(cfg)).Login(ctx, opts)
	case "profile":
		return NewAWSProfileFlow().Login(ctx, opts)
	default:
		return nil, fmt.Errorf("aws: %w: %s", ErrAuthMethodUnsupported, method)
	}
}

func (p *AWSProvider) loginSSO(ctx context.Context, opts map[string]string) (*Credential, error) {
	if p.ssoFlow == nil {
		region := opts["region"]
		if region == "" {
			region = "us-east-1"
		}
		cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
		if err != nil {
			return nil, fmt.Errorf("aws: load config: %w", err)
		}
		p.ssoFlow = NewAWSSSOFlow(ssooidc.NewFromConfig(cfg))
	}
	return p.ssoFlow.Login(ctx, opts)
}

func (p *AWSProvider) Validate(_ context.Context, cred *Credential) error {
	if cred == nil || (cred.Token == "" && cred.Method != "profile") {
		return fmt.Errorf("aws: invalid credential")
	}
	return nil
}

func (p *AWSProvider) Logout(_ context.Context) error {
	return nil
}

func init() {
	Register("aws", NewAWSProvider())
}
