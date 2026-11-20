package azure_test

import (
	"context"
	"errors"
	"testing"

	azruntime "github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/n24q02m/skret/internal/config"
	"github.com/n24q02m/skret/internal/provider"
	skazure "github.com/n24q02m/skret/internal/provider/azure"
)

// sparseListings wraps the in-memory vault so every listing page also carries
// a nil entry and an entry without an ID, shapes a partial service response
// can produce.
type sparseListings struct {
	*fakeVault
}

func withHoles(page []*azsecrets.SecretProperties) []*azsecrets.SecretProperties {
	return append([]*azsecrets.SecretProperties{nil, {}}, page...)
}

func (s sparseListings) NewListSecretPropertiesPager(opts *azsecrets.ListSecretPropertiesOptions) *azruntime.Pager[azsecrets.ListSecretPropertiesResponse] {
	inner := s.fakeVault.NewListSecretPropertiesPager(opts)
	return azruntime.NewPager(azruntime.PagingHandler[azsecrets.ListSecretPropertiesResponse]{
		More: func(azsecrets.ListSecretPropertiesResponse) bool { return inner.More() },
		Fetcher: func(ctx context.Context, _ *azsecrets.ListSecretPropertiesResponse) (azsecrets.ListSecretPropertiesResponse, error) {
			page, err := inner.NextPage(ctx)
			if err != nil {
				return page, err
			}
			page.Value = withHoles(page.Value)
			return page, nil
		},
	})
}

func (s sparseListings) NewListSecretPropertiesVersionsPager(name string, opts *azsecrets.ListSecretPropertiesVersionsOptions) *azruntime.Pager[azsecrets.ListSecretPropertiesVersionsResponse] {
	inner := s.fakeVault.NewListSecretPropertiesVersionsPager(name, opts)
	return azruntime.NewPager(azruntime.PagingHandler[azsecrets.ListSecretPropertiesVersionsResponse]{
		More: func(azsecrets.ListSecretPropertiesVersionsResponse) bool { return inner.More() },
		Fetcher: func(ctx context.Context, _ *azsecrets.ListSecretPropertiesVersionsResponse) (azsecrets.ListSecretPropertiesVersionsResponse, error) {
			page, err := inner.NextPage(ctx)
			if err != nil {
				return page, err
			}
			page.Value = withHoles(page.Value)
			return page, nil
		},
	})
}

// An invalid AZURE_TOKEN_CREDENTIALS selection makes the credential chain
// unbuildable; New reports it under the "no usable credential" envelope
// instead of returning a provider that would fail on first use.
func TestNew_InvalidCredentialSelectionIsReported(t *testing.T) {
	t.Setenv("AZURE_TOKEN_CREDENTIALS", "not-a-credential")

	p, err := skazure.New(&config.ResolvedConfig{Provider: "azure", VaultName: "somevault"})
	assert.Nil(t, p)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "azure: no usable credential")
	assert.Contains(t, err.Error(), `invalid AZURE_TOKEN_CREDENTIALS value "not-a-credential"`)
}

// Listing entries that are nil or carry no ID are skipped by every listing
// consumer: the results equal those of the same vault without the holes.
func TestListingsSkipEntriesWithoutID(t *testing.T) {
	ctx := context.Background()
	v := newFakeVault(map[string][]string{"A-KEY": {"va"}, "B-KEY": {"vb1", "vb2"}})
	plain := newProvider(v)
	sparse := skazure.NewWithClient(sparseListings{v}, "")

	wantList, err := plain.List(ctx, "")
	require.NoError(t, err)
	gotList, err := sparse.List(ctx, "")
	require.NoError(t, err)
	assert.Equal(t, wantList, gotList)

	wantNames, err := plain.ListNames(ctx, "")
	require.NoError(t, err)
	gotNames, err := sparse.ListNames(ctx, "")
	require.NoError(t, err)
	assert.Equal(t, wantNames, gotNames)
	assert.Contains(t, gotNames, "A-KEY")

	wantFP, err := plain.Fingerprint(ctx, "")
	require.NoError(t, err)
	gotFP, err := sparse.Fingerprint(ctx, "")
	require.NoError(t, err)
	assert.Equal(t, wantFP, gotFP)

	history, err := sparse.GetHistory(ctx, "B-KEY")
	require.NoError(t, err)
	require.Len(t, history, 2)
	assert.Equal(t, "vb1", history[0].Value)
	assert.Equal(t, "vb2", history[1].Value)

	s, err := sparse.(provider.VersionedReader).GetVersion(ctx, "B-KEY", 2)
	require.NoError(t, err)
	assert.Equal(t, "vb2", s.Value)
	assert.Equal(t, int64(2), s.Version)
}

// A failure while enumerating versions to resolve a version number is
// mapped under get_version and keeps the cause; it is not a miss.
func TestGetVersion_VersionListingErrorKeepsCause(t *testing.T) {
	v := newFakeVault(map[string][]string{"API-KEY": {"v1"}})
	cause := errors.New("connection reset")
	v.versErr = cause

	_, err := newProvider(v).(provider.VersionedReader).GetVersion(context.Background(), "API-KEY", 1)
	require.ErrorIs(t, err, cause)
	assert.NotErrorIs(t, err, provider.ErrNotFound)
	assert.Contains(t, err.Error(), `azure: get_version "API-KEY"`)
}

// A value read failing after the version number resolved is mapped under
// get_version and keeps the cause.
func TestGetVersion_ValueReadErrorKeepsCause(t *testing.T) {
	v := newFakeVault(map[string][]string{"API-KEY": {"v1"}})
	cause := errors.New("connection reset")
	v.getErr = cause

	_, err := newProvider(v).(provider.VersionedReader).GetVersion(context.Background(), "API-KEY", 1)
	require.ErrorIs(t, err, cause)
	assert.NotErrorIs(t, err, provider.ErrNotFound)
	assert.Contains(t, err.Error(), `azure: get_version "API-KEY"`)
}

// List fails the whole listing when one value read fails, naming the secret.
func TestList_ValueReadErrorNamesSecret(t *testing.T) {
	v := newFakeVault(map[string][]string{"A-KEY": {"va"}})
	cause := errors.New("connection reset")
	v.getErr = cause

	got, err := newProvider(v).List(context.Background(), "")
	assert.Nil(t, got)
	require.ErrorIs(t, err, cause)
	assert.Contains(t, err.Error(), `azure: list "A-KEY"`)
}

// Set stops before writing when the baseline read fails with anything other
// than not-found, and the value never appears in the error.
func TestSet_BaselineReadErrorStopsBeforeWrite(t *testing.T) {
	v := newFakeVault(map[string][]string{"K": {"old"}})
	cause := errors.New("connection reset")
	v.getErr = cause

	err := newProvider(v).Set(context.Background(), "K", "fixture-new-value", provider.SecretMeta{})
	require.ErrorIs(t, err, cause)
	assert.Contains(t, err.Error(), `azure: set "K"`)
	assert.NotContains(t, err.Error(), "fixture-new-value")
	assert.Empty(t, v.setInputs, "no write after a failed baseline read")
}

// Delete and GetHistory treat a key that sanitizes to no Key Vault name as
// absent and never call the service.
func TestDeleteAndHistory_ImpossibleKeyIsNotFound(t *testing.T) {
	v := newFakeVault(nil)
	v.delErr = errors.New("service must not be called")
	v.versErr = v.delErr
	p := newProvider(v)

	err := p.Delete(context.Background(), "###")
	require.ErrorIs(t, err, provider.ErrNotFound)
	assert.Contains(t, err.Error(), `azure: delete "###"`)
	assert.Empty(t, v.delInputs)

	_, err = p.GetHistory(context.Background(), "###")
	require.ErrorIs(t, err, provider.ErrNotFound)
	assert.Contains(t, err.Error(), `azure: history "###"`)
}
