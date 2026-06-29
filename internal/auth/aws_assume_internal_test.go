package auth

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/stretchr/testify/assert"
)

type mockAssumeSTS struct{}

func (f *mockAssumeSTS) AssumeRole(_ context.Context, _ *sts.AssumeRoleInput, _ ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	return nil, nil
}

func TestNewAWSAssumeFlow(t *testing.T) {
	client := &mockAssumeSTS{}
	flow := NewAWSAssumeFlow(client)
	assert.Equal(t, client, flow.client)
}
