package aws_test

import (
	"context"
	"errors"
	"testing"

	awslib "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/n24q02m/skret/internal/provider"
	skaws "github.com/n24q02m/skret/internal/provider/aws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type tagReadbackMock struct {
	*mockSSMClient
	tags map[string][]ssmtypes.Tag
}

func (m *tagReadbackMock) ListTagsForResource(_ context.Context, input *ssm.ListTagsForResourceInput, _ ...func(*ssm.Options)) (*ssm.ListTagsForResourceOutput, error) {
	m.callOrder = append(m.callOrder, "ListTagsForResource")
	return &ssm.ListTagsForResourceOutput{TagList: m.tags[awslib.ToString(input.ResourceId)]}, nil
}

func TestAWS_SetExistingTagFailureSurfacesReadbackBoundPartialCommit(t *testing.T) {
	const key = "/test/prod/PARTIAL"
	const value = "fixture-secret-value"
	apiErr := &mockAWSAPIError{code: "AccessDeniedException", message: "tag access denied"}
	base := &mockSSMClient{params: map[string]ssmtypes.Parameter{
		key: {Name: awslib.String(key), Value: awslib.String("old"), Version: 4},
	}}
	base.AddTagsToResourceFunc = func(_ context.Context, _ *ssm.AddTagsToResourceInput) (*ssm.AddTagsToResourceOutput, error) {
		return nil, apiErr
	}
	mock := &tagReadbackMock{
		mockSSMClient: base,
		tags: map[string][]ssmtypes.Tag{
			key: {{Key: awslib.String("env"), Value: awslib.String("old")}},
		},
	}

	p := skaws.NewWithClient(mock, "/test/prod")
	err := p.Set(context.Background(), key, value, provider.SecretMeta{
		Tags: map[string]string{"env": "new"},
	})

	var partial *provider.PartialCommitError
	require.ErrorAs(t, err, &partial)
	assert.ErrorIs(t, err, provider.ErrPartialCommit)
	assert.Equal(t, key, partial.Key)
	assert.Equal(t, int64(1), partial.Version)
	assert.Equal(t, int64(1), partial.ObservedVersion)
	assert.Equal(t, provider.TagReconciliationRequired, partial.TagState)
	assert.Contains(t, err.Error(), "value committed")
	assert.Contains(t, err.Error(), "tag reconciliation required")
	assert.NotContains(t, err.Error(), value)
	assert.Equal(t, []string{"GetParameter", "PutParameter", "AddTagsToResource", "GetParameter", "ListTagsForResource"}, mock.callOrder)
}

func TestAWS_SetExistingTagFailureReturnsSuccessAfterExactReadback(t *testing.T) {
	const key = "/test/prod/PARTIAL_EXACT"
	base := &mockSSMClient{params: map[string]ssmtypes.Parameter{
		key: {Name: awslib.String(key), Value: awslib.String("old"), Version: 4},
	}}
	base.AddTagsToResourceFunc = func(_ context.Context, _ *ssm.AddTagsToResourceInput) (*ssm.AddTagsToResourceOutput, error) {
		return nil, errors.New("ambiguous timeout")
	}
	mock := &tagReadbackMock{
		mockSSMClient: base,
		tags: map[string][]ssmtypes.Tag{
			key: {{Key: awslib.String("env"), Value: awslib.String("new")}},
		},
	}
	p := skaws.NewWithClient(mock, "/test/prod")

	assert.NoError(t, p.Set(context.Background(), key, "new", provider.SecretMeta{Tags: map[string]string{"env": "new"}}))
}

func TestAWS_SetAmbiguousPutUsesSingleAttemptAndReconcilesCommittedVersion(t *testing.T) {
	const key = "/test/prod/AMBIGUOUS_PUT"
	const value = "fixture-secret-value"
	base := &mockSSMClient{params: map[string]ssmtypes.Parameter{
		key: {Name: awslib.String(key), Value: awslib.String("old"), Version: 4},
	}}
	base.PutParameterFunc = func(_ context.Context, input *ssm.PutParameterInput) (*ssm.PutParameterOutput, error) {
		base.params[key] = ssmtypes.Parameter{
			Name:    awslib.String(key),
			Value:   input.Value,
			Version: 5,
		}
		return nil, errors.New("request timeout after commit")
	}
	mock := &tagReadbackMock{
		mockSSMClient: base,
		tags: map[string][]ssmtypes.Tag{
			key: {{Key: awslib.String("env"), Value: awslib.String("old")}},
		},
	}
	p := skaws.NewWithClient(mock, "/test/prod")
	err := p.Set(context.Background(), key, value, provider.SecretMeta{
		Tags: map[string]string{"env": "new"},
	})

	var partial *provider.PartialCommitError
	require.ErrorAs(t, err, &partial)
	assert.ErrorIs(t, err, provider.ErrPartialCommit)
	assert.Equal(t, int64(5), partial.Version)
	assert.Equal(t, int64(5), partial.ObservedVersion)
	assert.Equal(t, int64(4), partial.PreVersion)
	assert.Equal(t, provider.TagReconciliationRequired, partial.TagState)
	assert.NotContains(t, err.Error(), value)
	assert.Equal(t, []int{1}, mock.putRetryMaxAttempts)
	assert.Equal(t, []string{"GetParameter", "PutParameter", "GetParameter", "ListTagsForResource"}, mock.callOrder)
}
