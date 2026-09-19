package aws_test

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"testing"

	awslib "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/n24q02m/skret/internal/provider"
	skaws "github.com/n24q02m/skret/internal/provider/aws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countingSSMClient wraps mockSSMClient and counts read API calls so tests
// can assert batch sizing and cache hits against the provider contract:
// N keys cost ceil(N/10) GetParameters calls, and a warm cache costs zero.
type countingSSMClient struct {
	*mockSSMClient

	getParameterCalls    int
	getParametersCalls   int
	getByPathCalls       int
	batchRequestSizes    []int
	failBatchContaining  string
	batchFailureIsArmed  bool
	getParameterErrAfter int // -1 = never fail
}

func newCountingClient(params map[string]ssmtypes.Parameter) *countingSSMClient {
	return &countingSSMClient{
		mockSSMClient:        &mockSSMClient{params: params},
		getParameterErrAfter: -1,
	}
}

func (c *countingSSMClient) GetParameter(ctx context.Context, input *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
	c.getParameterCalls++
	if c.getParameterErrAfter >= 0 && c.getParameterCalls > c.getParameterErrAfter {
		return nil, &ssmtypes.ParameterNotFound{Message: awslib.String("counting-client not found")}
	}
	return c.mockSSMClient.GetParameter(ctx, input, optFns...)
}

func (c *countingSSMClient) GetParameters(ctx context.Context, input *ssm.GetParametersInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersOutput, error) {
	c.getParametersCalls++
	c.batchRequestSizes = append(c.batchRequestSizes, len(input.Names))
	if c.failBatchContaining != "" {
		for _, name := range input.Names {
			if name == c.failBatchContaining {
				c.batchFailureIsArmed = true
				return nil, errors.New("get_batch failure")
			}
		}
	}
	return c.mockSSMClient.GetParameters(ctx, input, optFns...)
}

func (c *countingSSMClient) GetParametersByPath(ctx context.Context, input *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
	c.getByPathCalls++
	return c.mockSSMClient.GetParametersByPath(ctx, input, optFns...)
}

// batchParams builds num parameters named K1..KNum with values V1..VNum and
// versions 1..num.
func batchParams(num int) map[string]ssmtypes.Parameter {
	params := make(map[string]ssmtypes.Parameter, num)
	for i := 1; i <= num; i++ {
		name := "K" + strconv.Itoa(i)
		version := int64(i)
		params[name] = ssmtypes.Parameter{
			Name:    awslib.String(name),
			Value:   awslib.String("V" + strconv.Itoa(i)),
			Version: version,
		}
	}
	return params
}

func batchKeys(num int) []string {
	keys := make([]string, 0, num)
	for i := 1; i <= num; i++ {
		keys = append(keys, "K"+strconv.Itoa(i))
	}
	return keys
}

// TestAWS_GetBatch_ChunkingAtLimit proves the spec ceiling: 25 keys cost at
// most 3 GetParameters calls, chunked 10/10/5, and every value comes back.
func TestAWS_GetBatch_ChunkingAtLimit(t *testing.T) {
	tests := []struct {
		name      string
		numKeys   int
		wantCalls int
		wantSizes []int
	}{
		{"exactly one chunk", 10, 1, []int{10}},
		{"one over the limit", 11, 2, []int{10, 1}},
		{"two full chunks", 20, 2, []int{10, 10}},
		{"25 keys within 3 calls", 25, 3, []int{10, 10, 5}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newCountingClient(batchParams(tt.numKeys))
			p := skaws.NewWithClient(client, "/test/")

			secrets, err := p.GetBatch(context.Background(), batchKeys(tt.numKeys))
			require.NoError(t, err)
			require.Len(t, secrets, tt.numKeys)

			assert.LessOrEqual(t, client.getParametersCalls, tt.wantCalls, "API calls must stay within the batch ceiling")
			require.Len(t, client.batchRequestSizes, tt.wantCalls)
			assert.Equal(t, tt.wantSizes, client.batchRequestSizes, "each chunk must hold at most 10 names")
			for _, s := range secrets {
				i := 0
				_, err := fmt.Sscanf(s.Key, "K%d", &i)
				require.NoError(t, err)
				assert.Equal(t, "V"+strconv.Itoa(i), s.Value)
				assert.Equal(t, int64(i), s.Version)
			}
		})
	}
}

// TestAWS_GetBatch_MidBatchErrorPropagates proves a failure in a later chunk
// surfaces the same error class instead of returning partial results.
func TestAWS_GetBatch_MidBatchErrorPropagates(t *testing.T) {
	client := newCountingClient(batchParams(25))
	// K11 lands in the second chunk; the first chunk must not mask the error.
	client.failBatchContaining = "K11"
	p := skaws.NewWithClient(client, "/test/")

	secrets, err := p.GetBatch(context.Background(), batchKeys(25))
	require.Error(t, err)
	assert.Nil(t, secrets, "a mid-batch failure must not yield partial results")
	assert.Contains(t, err.Error(), "get_batch failure")
	assert.True(t, client.batchFailureIsArmed, "the failing chunk must actually have been reached")
}

// TestAWS_GetBatch_CacheHitZeroRefetch proves a second GetBatch of the same
// keys within one process issues zero API calls and returns equal secrets.
func TestAWS_GetBatch_CacheHitZeroRefetch(t *testing.T) {
	client := newCountingClient(batchParams(25))
	p := skaws.NewWithClient(client, "/test/")
	keys := batchKeys(25)

	first, err := p.GetBatch(context.Background(), keys)
	require.NoError(t, err)
	require.Len(t, first, 25)
	require.Equal(t, 3, client.getParametersCalls)

	second, err := p.GetBatch(context.Background(), keys)
	require.NoError(t, err)
	assert.Equal(t, 3, client.getParametersCalls, "warm cache must issue zero additional GetParameters calls")
	require.Len(t, second, 25)
	for i := range first {
		assert.Equal(t, first[i].Key, second[i].Key)
		assert.Equal(t, first[i].Value, second[i].Value)
		assert.Equal(t, first[i].Version, second[i].Version)
	}
}

// TestAWS_Get_CacheHitZeroRefetch proves a repeated Get within one process
// skips the API entirely.
func TestAWS_Get_CacheHitZeroRefetch(t *testing.T) {
	client := newCountingClient(batchParams(1))
	p := skaws.NewWithClient(client, "/test/")

	first, err := p.Get(context.Background(), "K1")
	require.NoError(t, err)
	require.Equal(t, 1, client.getParameterCalls)

	second, err := p.Get(context.Background(), "K1")
	require.NoError(t, err)
	assert.Equal(t, 1, client.getParameterCalls, "cache hit must issue zero API calls")
	assert.Equal(t, first.Value, second.Value)
	assert.Equal(t, first.Version, second.Version)

	third, err := p.Get(context.Background(), "K1")
	require.NoError(t, err)
	assert.Equal(t, 1, client.getParameterCalls)
	assert.Equal(t, first.Value, third.Value)
}

// TestAWS_GetVersion_CacheKeyedByVersion proves the cache is keyed by
// (name, VersionId): the same version hits, a different version fetches.
func TestAWS_GetVersion_CacheKeyedByVersion(t *testing.T) {
	params := batchParams(1)
	params["K1:2"] = ssmtypes.Parameter{Name: awslib.String("K1"), Value: awslib.String("V1"), Version: 2}
	params["K1:1"] = ssmtypes.Parameter{Name: awslib.String("K1"), Value: awslib.String("old-V1"), Version: 1}
	client := newCountingClient(params)
	p := skaws.NewWithClient(client, "/test/")
	reader, ok := p.(provider.VersionedReader)
	require.True(t, ok)

	first, err := reader.GetVersion(context.Background(), "K1", 2)
	require.NoError(t, err)
	require.Equal(t, 1, client.getParameterCalls)

	second, err := reader.GetVersion(context.Background(), "K1", 2)
	require.NoError(t, err)
	assert.Equal(t, 1, client.getParameterCalls, "same (name, version) must hit the cache")
	assert.Equal(t, first.Value, second.Value)

	older, err := reader.GetVersion(context.Background(), "K1", 1)
	require.NoError(t, err)
	assert.Equal(t, 2, client.getParameterCalls, "a different version must fetch")
	assert.Equal(t, "old-V1", older.Value)
}

// TestAWS_SetInvalidatesCache proves a mutation through the same provider is
// observed by the next read: the cached entry is dropped and the value is
// re-fetched.
func TestAWS_SetInvalidatesCache(t *testing.T) {
	client := newCountingClient(batchParams(1))
	p := skaws.NewWithClient(client, "/test/")

	original, err := p.Get(context.Background(), "K1")
	require.NoError(t, err)
	require.Equal(t, 1, client.getParameterCalls)

	require.NoError(t, p.Set(context.Background(), "K1", "rotated", provider.SecretMeta{}))
	assert.Equal(t, "V1", original.Value, "the returned secret must not be mutated in place")

	fresh, err := p.Get(context.Background(), "K1")
	require.NoError(t, err)
	assert.Equal(t, "rotated", fresh.Value, "post-mutation read must observe the new value")
	assert.Greater(t, client.getParameterCalls, 2, "post-mutation read must re-fetch (Set's pre-write lookup + fresh Get)")
}

// TestAWS_DeleteInvalidatesCache proves a deleted key is not served from the
// cache and the not-found error class is preserved.
func TestAWS_DeleteInvalidatesCache(t *testing.T) {
	client := newCountingClient(batchParams(1))
	p := skaws.NewWithClient(client, "/test/")

	_, err := p.Get(context.Background(), "K1")
	require.NoError(t, err)
	require.NoError(t, p.Delete(context.Background(), "K1"))

	_, err = p.Get(context.Background(), "K1")
	assert.ErrorIs(t, err, provider.ErrNotFound)
}

// TestAWS_GetBatch_InputOrderDedupAndMissing proves deterministic results:
// input order preserved, duplicates emitted once, missing keys omitted.
func TestAWS_GetBatch_InputOrderDedupAndMissing(t *testing.T) {
	client := newCountingClient(batchParams(3))
	p := skaws.NewWithClient(client, "/test/")

	secrets, err := p.GetBatch(context.Background(), []string{"K3", "K1", "K1", "K9"})
	require.NoError(t, err)
	require.Len(t, secrets, 2)
	assert.Equal(t, "K3", secrets[0].Key)
	assert.Equal(t, "K1", secrets[1].Key)
}

// paginatedByPathFunc returns a GetParametersByPath hook that pages through
// the given names 10 at a time (the SSM default page size).
func paginatedByPathFunc(names []string, prefix string) func(context.Context, *ssm.GetParametersByPathInput) (*ssm.GetParametersByPathOutput, error) {
	return func(_ context.Context, input *ssm.GetParametersByPathInput) (*ssm.GetParametersByPathOutput, error) {
		start := 0
		if input.NextToken != nil {
			start, _ = strconv.Atoi(awslib.ToString(input.NextToken))
		}
		end := start + 10
		if end > len(names) {
			end = len(names)
		}
		out := &ssm.GetParametersByPathOutput{}
		for _, name := range names[start:end] {
			out.Parameters = append(out.Parameters, ssmtypes.Parameter{
				Name:    awslib.String(prefix + name),
				Value:   awslib.String("V-" + name),
				Version: 1,
			})
		}

		if end < len(names) {
			out.NextToken = awslib.String(strconv.Itoa(end))
		}
		return out, nil
	}
}

// TestAWS_List_25Keys_ThreeAPICalls proves the run/env read path: listing 25
// keys costs 3 paginated GetParametersByPath calls, never N single Gets.
func TestAWS_List_25Keys_ThreeAPICalls(t *testing.T) {
	names := batchKeys(25)
	client := newCountingClient(nil)
	client.GetParametersByPathFunc = paginatedByPathFunc(names, "/test/prod/")
	p := skaws.NewWithClient(client, "/test/prod/")

	secrets, err := p.List(context.Background(), "/test/prod/")
	require.NoError(t, err)
	require.Len(t, secrets, 25)
	assert.Equal(t, 3, client.getByPathCalls)
	assert.Equal(t, 0, client.getParameterCalls, "List must not degrade to per-key Gets")
}

// TestAWS_List_StaysLiveForChangeDetection proves List is never cached:
// `run --watch` relies on live reads to detect external changes.
func TestAWS_List_StaysLiveForChangeDetection(t *testing.T) {
	client := newCountingClient(batchParams(2))
	p := skaws.NewWithClient(client, "/test/")

	for i := 0; i < 3; i++ {
		_, err := p.List(context.Background(), "/test/")
		require.NoError(t, err)
	}
	assert.Equal(t, 3, client.getByPathCalls, "each List must be a live read")
}
