package auth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/n24q02m/skret/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockSTS struct {
	out *sts.AssumeRoleOutput
	err error
}

func (m *mockSTS) AssumeRole(_ context.Context, _ *sts.AssumeRoleInput, _ ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	return m.out, m.err
}

func TestAWSAssumeFlow_Success(t *testing.T) {
	exp := time.Now().Add(1 * time.Hour)
	m := &mockSTS{out: &sts.AssumeRoleOutput{
		Credentials: &ststypes.Credentials{
			AccessKeyId:     aws.String("AKIATEMP"),
			SecretAccessKey: aws.String("SECRETTEMP"),
			SessionToken:    aws.String("SESSION"),
			Expiration:      aws.Time(exp),
		},
	}}
	flow := auth.NewAWSAssumeFlow(m)
	cred, err := flow.Login(context.Background(), map[string]string{"role_arn": "arn:aws:iam::111:role/skret"})
	require.NoError(t, err)
	assert.Equal(t, "assume-role", cred.Method)
	assert.Equal(t, "SECRETTEMP", cred.Token)
	assert.Equal(t, "AKIATEMP", cred.Metadata["access_key_id"])
	assert.Equal(t, "SESSION", cred.Metadata["session_token"])
	assert.WithinDuration(t, exp, cred.ExpiresAt, time.Second)
}

func TestAWSAssumeFlow_MissingArn(t *testing.T) {
	flow := auth.NewAWSAssumeFlow(&mockSTS{})
	_, err := flow.Login(context.Background(), nil)
	require.Error(t, err)
}

func TestAWSAssumeFlow_STSError(t *testing.T) {
	flow := auth.NewAWSAssumeFlow(&mockSTS{err: errors.New("access denied")})
	_, err := flow.Login(context.Background(), map[string]string{"role_arn": "arn:x"})
	require.Error(t, err)
}
