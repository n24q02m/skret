package aws_test

import (
	"context"
	"errors"
	"testing"
	"time"

	awslib "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/n24q02m/skret/internal/provider"
	skaws "github.com/n24q02m/skret/internal/provider/aws"
)

// emptyReadClient answers GetParameter with a response that carries no
// parameter, which SSM never sends for a successful read.
type emptyReadClient struct{ *mockSSMClient }

func (c *emptyReadClient) GetParameter(_ context.Context, _ *ssm.GetParameterInput, _ ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
	c.callOrder = append(c.callOrder, "GetParameter")
	return &ssm.GetParameterOutput{}, nil
}

// untaggableClient exposes only the SSMClient methods, so the provider cannot
// tag or read tags through it.
type untaggableClient struct{ skaws.SSMClient }

// failingTagReader reads parameters normally but cannot list tags.
type failingTagReader struct{ *mockSSMClient }

func (c *failingTagReader) ListTagsForResource(_ context.Context, _ *ssm.ListTagsForResourceInput, _ ...func(*ssm.Options)) (*ssm.ListTagsForResourceOutput, error) {
	c.callOrder = append(c.callOrder, "ListTagsForResource")
	return nil, errors.New("tag listing unavailable")
}

func existingParam(key string, version int64) map[string]ssmtypes.Parameter {
	return map[string]ssmtypes.Parameter{
		key: {Name: awslib.String(key), Value: awslib.String("old"), Version: version},
	}
}

// Read guards: an empty key or a non-positive version never reaches the API,
// and a response without a parameter is a miss, not a zero-valued secret.
func TestAWS_ReadGuardsAndEmptyResponses(t *testing.T) {
	base := &mockSSMClient{params: map[string]ssmtypes.Parameter{}}
	p := skaws.NewWithClient(base, "/test/prod")
	reader, ok := p.(provider.VersionedReader)
	require.True(t, ok)

	_, err := p.Get(context.Background(), "")
	assert.ErrorIs(t, err, provider.ErrNotFound)
	_, err = reader.GetVersion(context.Background(), "/test/prod/KEY", 0)
	assert.ErrorIs(t, err, provider.ErrNotFound)
	assert.Empty(t, base.callOrder, "guarded reads must not call SSM")

	empty := skaws.NewWithClient(&emptyReadClient{mockSSMClient: base}, "/test/prod")
	_, err = empty.Get(context.Background(), "/test/prod/KEY")
	assert.ErrorIs(t, err, provider.ErrNotFound)
	_, err = empty.(provider.VersionedReader).GetVersion(context.Background(), "/test/prod/KEY", 3)
	assert.ErrorIs(t, err, provider.ErrNotFound)
}

// GetVersion rejects a response for a different version than the selector
// asked for, and carries LastModifiedDate into the secret metadata.
func TestAWS_GetVersionVerifiesReturnedVersion(t *testing.T) {
	modified := time.Date(2026, 11, 1, 8, 0, 0, 0, time.UTC)
	p := newTestProvider(map[string]ssmtypes.Parameter{
		"/test/prod/KEY:2": {Name: awslib.String("/test/prod/KEY"), Value: awslib.String("v3"), Version: 3},
		"/test/prod/KEY:4": {
			Name: awslib.String("/test/prod/KEY"), Value: awslib.String("v4"), Version: 4,
			LastModifiedDate: &modified,
		},
	})
	reader := p.(provider.VersionedReader)

	_, err := reader.GetVersion(context.Background(), "/test/prod/KEY", 2)
	assert.ErrorIs(t, err, provider.ErrNotFound)

	secret, err := reader.GetVersion(context.Background(), "/test/prod/KEY", 4)
	require.NoError(t, err)
	assert.Equal(t, modified, secret.Meta.UpdatedAt)
}

// GetBatch with no keys is a no-op, and batch and list reads both carry
// LastModifiedDate into the metadata.
func TestAWS_BatchAndListCarryLastModified(t *testing.T) {
	modified := time.Date(2026, 11, 2, 9, 30, 0, 0, time.UTC)
	base := &mockSSMClient{params: map[string]ssmtypes.Parameter{
		"/test/prod/KEY": {Name: awslib.String("/test/prod/KEY"), Value: awslib.String("v"), Version: 1, LastModifiedDate: &modified},
	}}
	p := skaws.NewWithClient(base, "/test/prod")

	none, err := p.GetBatch(context.Background(), nil)
	require.NoError(t, err)
	assert.Nil(t, none)

	batch, err := p.GetBatch(context.Background(), []string{"/test/prod/KEY"})
	require.NoError(t, err)
	require.Len(t, batch, 1)
	assert.Equal(t, modified, batch[0].Meta.UpdatedAt)

	listed, err := p.List(context.Background(), "/test/prod")
	require.NoError(t, err)
	require.Len(t, listed, 1)
	assert.Equal(t, modified, listed[0].Meta.UpdatedAt)
}

// A pre-write readback that succeeds without a parameter is not trusted as
// "exists" or "missing": Set refuses to write.
func TestAWS_SetRejectsInvalidPreWriteReadback(t *testing.T) {
	base := &mockSSMClient{params: map[string]ssmtypes.Parameter{}}
	p := skaws.NewWithClient(&emptyReadClient{mockSSMClient: base}, "/test/prod")

	err := p.Set(context.Background(), "/test/prod/KEY", "fixture-secret-value", provider.SecretMeta{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid pre-write readback")
	assert.NotContains(t, err.Error(), "fixture-secret-value")
	assert.Empty(t, base.putInputs, "no write may follow an invalid readback")
}

// A non-zero ExpiresAt is mirrored to the reserved expiry tag in UTC RFC3339
// and wins over a user tag of the same name.
func TestAWS_SetMirrorsExpiryIntoTags(t *testing.T) {
	base := &mockSSMClient{params: map[string]ssmtypes.Parameter{}}
	p := skaws.NewWithClient(base, "/test/prod")
	expires := time.Date(2027, 1, 2, 3, 4, 5, 0, time.FixedZone("ICT", 7*3600))

	require.NoError(t, p.Set(context.Background(), "/test/prod/KEY", "v", provider.SecretMeta{
		ExpiresAt: expires,
		Tags:      map[string]string{skaws.TagExpiresAt: "user-value", "env": "prod"},
	}))
	require.Len(t, base.putInputs, 1)
	got := map[string]string{}
	for _, tag := range base.putInputs[0].Tags {
		got[awslib.ToString(tag.Key)] = awslib.ToString(tag.Value)
	}
	assert.Equal(t, map[string]string{skaws.TagExpiresAt: "2027-01-01T20:04:05Z", "env": "prod"}, got)
}

// A client that cannot tag still gets the value written; the missing tag step
// is reported as a partial commit whose tag state is unknown.
func TestAWS_SetExistingWithoutTaggerReportsPartialCommit(t *testing.T) {
	const key = "/test/prod/UNTAGGABLE"
	base := &mockSSMClient{params: existingParam(key, 4)}
	p := skaws.NewWithClient(untaggableClient{SSMClient: base}, "/test/prod")

	err := p.Set(context.Background(), key, "fixture-secret-value", provider.SecretMeta{Tags: map[string]string{"env": "new"}})

	var partial *provider.PartialCommitError
	require.ErrorAs(t, err, &partial)
	assert.Equal(t, int64(4), partial.PreVersion)
	assert.Equal(t, int64(1), partial.Version)
	assert.Equal(t, int64(1), partial.ObservedVersion)
	assert.Equal(t, provider.TagReconciliationUnknown, partial.TagState)
	assert.NotContains(t, err.Error(), "fixture-secret-value")
}

// When the tag readback itself fails after a tag write error, the tag state is
// reported as unknown rather than matched or mismatched.
func TestAWS_SetTagReadbackFailureIsUnknown(t *testing.T) {
	const key = "/test/prod/TAG_READ_FAIL"
	base := &mockSSMClient{params: existingParam(key, 4)}
	base.AddTagsToResourceFunc = func(context.Context, *ssm.AddTagsToResourceInput) (*ssm.AddTagsToResourceOutput, error) {
		return nil, errors.New("tag write timeout")
	}
	client := &failingTagReader{mockSSMClient: base}
	p := skaws.NewWithClient(client, "/test/prod")

	err := p.Set(context.Background(), key, "new", provider.SecretMeta{Tags: map[string]string{"env": "new"}})

	var partial *provider.PartialCommitError
	require.ErrorAs(t, err, &partial)
	assert.Equal(t, int64(1), partial.ObservedVersion)
	assert.Equal(t, provider.TagReconciliationUnknown, partial.TagState)
	assert.Equal(t, []string{"GetParameter", "PutParameter", "AddTagsToResource", "GetParameter", "ListTagsForResource"}, client.callOrder)
}

// A successful put whose response omits the version is reconciled from the
// readback: when the observed version carries exactly the requested tags the
// write is complete even though the tag call errored.
func TestAWS_SetVersionlessPutReconciledFromReadback(t *testing.T) {
	const key = "/test/prod/VERSIONLESS"
	base := &mockSSMClient{params: existingParam(key, 4)}
	base.PutParameterFunc = func(_ context.Context, input *ssm.PutParameterInput) (*ssm.PutParameterOutput, error) {
		base.params[key] = ssmtypes.Parameter{Name: input.Name, Value: input.Value, Version: 5}
		return &ssm.PutParameterOutput{}, nil
	}
	base.AddTagsToResourceFunc = func(context.Context, *ssm.AddTagsToResourceInput) (*ssm.AddTagsToResourceOutput, error) {
		return nil, errors.New("tag response lost")
	}
	client := &tagReadbackMock{mockSSMClient: base, tags: map[string][]ssmtypes.Tag{
		key: {{Key: awslib.String("env"), Value: awslib.String("new")}},
	}}
	p := skaws.NewWithClient(client, "/test/prod")

	assert.NoError(t, p.Set(context.Background(), key, "new", provider.SecretMeta{Tags: map[string]string{"env": "new"}}))
}

// A versionless put followed by a failed readback leaves nothing known: the
// error says the commit state itself is unknown.
func TestAWS_SetVersionlessPutWithFailedReadbackIsCommitUnknown(t *testing.T) {
	const key = "/test/prod/VERSIONLESS_UNKNOWN"
	base := &mockSSMClient{params: existingParam(key, 4)}
	base.PutParameterFunc = func(context.Context, *ssm.PutParameterInput) (*ssm.PutParameterOutput, error) {
		base.errGet = errors.New("readback unavailable")
		return nil, nil
	}
	base.AddTagsToResourceFunc = func(context.Context, *ssm.AddTagsToResourceInput) (*ssm.AddTagsToResourceOutput, error) {
		return nil, errors.New("tag response lost")
	}
	p := skaws.NewWithClient(base, "/test/prod")

	err := p.Set(context.Background(), key, "fixture-secret-value", provider.SecretMeta{Tags: map[string]string{"env": "new"}})

	var partial *provider.PartialCommitError
	require.ErrorAs(t, err, &partial)
	assert.Equal(t, provider.MutationCommitUnknown, partial.CommitState)
	assert.Zero(t, partial.Version)
	assert.Zero(t, partial.ObservedVersion)
	assert.Equal(t, provider.TagReconciliationUnknown, partial.TagState)
	assert.NotContains(t, err.Error(), "fixture-secret-value")
}

// An ambiguous put that reported a version, followed by a failed readback,
// keeps the reported version but marks the commit itself as unknown.
func TestAWS_SetAmbiguousPutWithFailedReadbackIsCommitUnknown(t *testing.T) {
	const key = "/test/prod/AMBIGUOUS_UNKNOWN"
	base := &mockSSMClient{params: existingParam(key, 4)}
	base.PutParameterFunc = func(context.Context, *ssm.PutParameterInput) (*ssm.PutParameterOutput, error) {
		base.errGet = errors.New("readback unavailable")
		return &ssm.PutParameterOutput{Version: 5}, errors.New("request timeout")
	}
	p := skaws.NewWithClient(base, "/test/prod")

	err := p.Set(context.Background(), key, "fixture-secret-value", provider.SecretMeta{})

	var partial *provider.PartialCommitError
	require.ErrorAs(t, err, &partial)
	assert.Equal(t, provider.MutationCommitUnknown, partial.CommitState)
	assert.Equal(t, int64(5), partial.Version)
	assert.Zero(t, partial.ObservedVersion)
	assert.Equal(t, int64(4), partial.PreVersion)
	assert.NotContains(t, err.Error(), "fixture-secret-value")
}

// An ambiguous put whose readback still shows the old version did not commit:
// the original put error is returned, not a partial commit.
func TestAWS_SetAmbiguousPutNotCommittedReturnsCause(t *testing.T) {
	const key = "/test/prod/AMBIGUOUS_NOT_COMMITTED"
	base := &mockSSMClient{params: existingParam(key, 4)}
	base.PutParameterFunc = func(context.Context, *ssm.PutParameterInput) (*ssm.PutParameterOutput, error) {
		return &ssm.PutParameterOutput{Version: 5}, errors.New("request timeout before commit")
	}
	p := skaws.NewWithClient(base, "/test/prod")

	err := p.Set(context.Background(), key, "fixture-secret-value", provider.SecretMeta{})

	require.Error(t, err)
	assert.NotErrorIs(t, err, provider.ErrPartialCommit)
	assert.Contains(t, err.Error(), `aws: set "/test/prod/AMBIGUOUS_NOT_COMMITTED"`)
	assert.Contains(t, err.Error(), "request timeout before commit")
}

// An ambiguous put without tags whose readback shows exactly the reported
// version committed: Set succeeds.
func TestAWS_SetAmbiguousPutCommittedWithoutTagsSucceeds(t *testing.T) {
	const key = "/test/prod/AMBIGUOUS_COMMITTED"
	base := &mockSSMClient{params: existingParam(key, 4)}
	base.PutParameterFunc = func(_ context.Context, input *ssm.PutParameterInput) (*ssm.PutParameterOutput, error) {
		base.params[key] = ssmtypes.Parameter{Name: input.Name, Value: input.Value, Version: 5}
		return &ssm.PutParameterOutput{Version: 5}, errors.New("response lost after commit")
	}
	p := skaws.NewWithClient(base, "/test/prod")

	assert.NoError(t, p.Set(context.Background(), key, "new", provider.SecretMeta{}))
}
