package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// STSAssumer is the subset of the STS client used by the assume-role flow.
type STSAssumer interface {
	AssumeRole(ctx context.Context, in *sts.AssumeRoleInput, opts ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
}

// AWSAssumeFlow performs an STS AssumeRole call and returns temporary
// credentials with expiration tracking.
type AWSAssumeFlow struct {
	client STSAssumer
}

// NewAWSAssumeFlow creates an assume-role flow backed by the given STS client.
func NewAWSAssumeFlow(client STSAssumer) *AWSAssumeFlow {
	return &AWSAssumeFlow{client: client}
}

// Login assumes opts["role_arn"] using opts["session_name"] (defaults to
// "skret-cli") and returns the resulting temporary credential.
func (f *AWSAssumeFlow) Login(ctx context.Context, opts map[string]string) (*Credential, error) {
	roleArn := opts["role_arn"]
	if roleArn == "" {
		return nil, fmt.Errorf("aws assume: role_arn required")
	}
	sessionName := opts["session_name"]
	if sessionName == "" {
		sessionName = "skret-cli"
	}
	out, err := f.client.AssumeRole(ctx, &sts.AssumeRoleInput{
		RoleArn:         aws.String(roleArn),
		RoleSessionName: aws.String(sessionName),
	})
	if err != nil {
		return nil, fmt.Errorf("aws assume: %w", err)
	}
	if out.Credentials == nil {
		return nil, fmt.Errorf("aws assume: sts returned nil credentials")
	}
	exp := time.Time{}
	if out.Credentials.Expiration != nil {
		exp = *out.Credentials.Expiration
	}
	return &Credential{
		Method:    "assume-role",
		Token:     aws.ToString(out.Credentials.SecretAccessKey),
		ExpiresAt: exp,
		Metadata: map[string]string{
			"access_key_id": aws.ToString(out.Credentials.AccessKeyId),
			"session_token": aws.ToString(out.Credentials.SessionToken),
			"role_arn":      roleArn,
		},
	}, nil
}
