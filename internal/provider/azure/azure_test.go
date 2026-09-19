package azure_test

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	azruntime "github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/n24q02m/skret/internal/config"
	"github.com/n24q02m/skret/internal/provider"
	skazure "github.com/n24q02m/skret/internal/provider/azure"
)

// ---------------------------------------------------------------------------
// In-memory Key Vault implementing the provider's SecretsClient surface.
// ---------------------------------------------------------------------------

const fakeVaultURL = "https://test-vault.vault.azure.net"

// hexVersion renders a decimal counter as a Key Vault-shaped 32-char hex ID
// with the counter inside the first 15 characters, the window versionNumber
// folds on, so seeded versions get distinct folded numbers.
func hexVersion(n int) string { return fmt.Sprintf("%015x%017x", n, 0) }

type fakeVersion struct {
	id      string
	value   string
	tags    map[string]*string
	created time.Time
	updated time.Time
}

type fakeVault struct {
	// secrets maps name -> versions, index 0 = newest.
	secrets     map[string][]*fakeVersion
	getErr      error
	readbackErr error // returned by GetSecret only after SetSecret was called
	// readbackVersion, when set, is what GetSecret returns after a
	// SetSecret call, standing in for another writer's version.
	readbackVersion *fakeVersion
	setErr          error
	delErr          error
	listErr         error
	versErr         error
	getCalls        int
	setInputs       []azsecrets.SetSecretParameters
	delInputs       []string
	nextVer         int
}

// newFakeVault seeds versions oldest-first for readability; they are stored
// newest-first like Key Vault's version listing.
func newFakeVault(seeded map[string][]string) *fakeVault {
	v := &fakeVault{secrets: map[string][]*fakeVersion{}, nextVer: len(seeded) * 3}
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	for name, values := range seeded {
		for i, val := range values {
			ver := i + 1
			v.secrets[name] = append([]*fakeVersion{{
				id:      fakeVaultURL + "/secrets/" + name + "/" + hexVersion(ver),
				value:   val,
				created: now.Add(time.Duration(ver) * time.Minute),
				updated: now.Add(time.Duration(ver) * time.Minute),
			}}, v.secrets[name]...)
		}
	}
	return v
}

func notFound() error {
	return &azcore.ResponseError{ErrorCode: "SecretNotFound", StatusCode: 404}
}

func (v *fakeVault) GetSecret(_ context.Context, name, version string, _ *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error) {
	v.getCalls++
	afterSet := len(v.setInputs) > 0
	if afterSet && v.readbackErr != nil {
		return azsecrets.GetSecretResponse{}, v.readbackErr
	}
	if afterSet && v.readbackVersion != nil {
		fv := v.readbackVersion
		return azsecrets.GetSecretResponse{Secret: azsecrets.Secret{
			Value:      new(fv.value),
			ID:         new(azsecrets.ID(fv.id)),
			Tags:       fv.tags,
			Attributes: &azsecrets.SecretAttributes{Created: new(fv.created), Updated: new(fv.updated)},
		}}, nil
	}
	if v.getErr != nil {
		return azsecrets.GetSecretResponse{}, v.getErr
	}
	versions, ok := v.secrets[name]
	if !ok || len(versions) == 0 {
		return azsecrets.GetSecretResponse{}, notFound()
	}
	fv := versions[0]
	if version != "" {
		found := false
		for _, cand := range versions {
			if cand.id[len(cand.id)-len(version):] == version {
				fv, found = cand, true
				break
			}
		}
		if !found {
			return azsecrets.GetSecretResponse{}, notFound()
		}
	}
	return azsecrets.GetSecretResponse{Secret: azsecrets.Secret{
		Value:      new(fv.value),
		ID:         new(azsecrets.ID(fv.id)),
		Tags:       fv.tags,
		Attributes: &azsecrets.SecretAttributes{Created: new(fv.created), Updated: new(fv.updated)},
	}}, nil
}

func (v *fakeVault) SetSecret(_ context.Context, name string, params azsecrets.SetSecretParameters, _ *azsecrets.SetSecretOptions) (azsecrets.SetSecretResponse, error) {
	v.setInputs = append(v.setInputs, params)
	if v.setErr != nil {
		// Model server semantics: a 4xx rejects before commit; an
		// ambiguous failure (5xx/transport) means the version DID land
		// and only the response was lost.
		var re *azcore.ResponseError
		if errors.As(v.setErr, &re) && re.StatusCode < 500 {
			return azsecrets.SetSecretResponse{}, v.setErr
		}
	}
	v.commitSecret(name, params)
	if v.setErr != nil {
		return azsecrets.SetSecretResponse{}, v.setErr
	}
	fv := v.secrets[name][0]
	return azsecrets.SetSecretResponse{Secret: azsecrets.Secret{Value: params.Value, ID: new(azsecrets.ID(fv.id))}}, nil
}

func (v *fakeVault) commitSecret(name string, params azsecrets.SetSecretParameters) {
	v.nextVer++
	fv := &fakeVersion{
		id:      fakeVaultURL + "/secrets/" + name + "/" + hexVersion(v.nextVer),
		value:   *params.Value,
		tags:    params.Tags,
		updated: time.Date(2026, 9, 19, 13, 0, 0, 0, time.UTC),
	}
	v.secrets[name] = append([]*fakeVersion{fv}, v.secrets[name]...)
}

func (v *fakeVault) DeleteSecret(_ context.Context, name string, _ *azsecrets.DeleteSecretOptions) (azsecrets.DeleteSecretResponse, error) {
	v.delInputs = append(v.delInputs, name)
	if v.delErr != nil {
		return azsecrets.DeleteSecretResponse{}, v.delErr
	}
	if _, ok := v.secrets[name]; !ok {
		return azsecrets.DeleteSecretResponse{}, notFound()
	}
	delete(v.secrets, name)
	return azsecrets.DeleteSecretResponse{}, nil
}

func (v *fakeVault) props(name string, versions []*fakeVersion) []*azsecrets.SecretProperties {
	props := make([]*azsecrets.SecretProperties, 0, len(versions))
	for _, fv := range versions {
		p := &azsecrets.SecretProperties{
			ID:         new(azsecrets.ID(fv.id)),
			Attributes: &azsecrets.SecretAttributes{Created: new(fv.created), Updated: new(fv.updated)},
		}
		if name == "managed-cert" {
			p.Managed = new(true)
		}
		props = append(props, p)
	}
	return props
}

func (v *fakeVault) NewListSecretPropertiesPager(_ *azsecrets.ListSecretPropertiesOptions) *azruntime.Pager[azsecrets.ListSecretPropertiesResponse] {
	// Two pages when several secrets exist so pagination is exercised.
	var all []*azsecrets.SecretProperties
	for _, name := range sortedNames(v.secrets) {
		all = append(all, v.props(name, v.secrets[name])...)
	}
	pages := [][]*azsecrets.SecretProperties{}
	if len(all) > 0 {
		if len(all) > 1 {
			pages = [][]*azsecrets.SecretProperties{all[:1], all[1:]}
		} else {
			pages = [][]*azsecrets.SecretProperties{all}
		}
	}
	idx := 0
	return azruntime.NewPager(azruntime.PagingHandler[azsecrets.ListSecretPropertiesResponse]{
		More: func(azsecrets.ListSecretPropertiesResponse) bool {
			return idx < len(pages)
		},
		Fetcher: func(context.Context, *azsecrets.ListSecretPropertiesResponse) (azsecrets.ListSecretPropertiesResponse, error) {
			if v.listErr != nil {
				return azsecrets.ListSecretPropertiesResponse{}, v.listErr
			}
			page := pages[idx]
			idx++
			return azsecrets.ListSecretPropertiesResponse{SecretPropertiesListResult: azsecrets.SecretPropertiesListResult{Value: page}}, nil
		},
	})
}

func (v *fakeVault) NewListSecretPropertiesVersionsPager(name string, _ *azsecrets.ListSecretPropertiesVersionsOptions) *azruntime.Pager[azsecrets.ListSecretPropertiesVersionsResponse] {
	_, exists := v.secrets[name]
	idx := 0
	return azruntime.NewPager(azruntime.PagingHandler[azsecrets.ListSecretPropertiesVersionsResponse]{
		More: func(azsecrets.ListSecretPropertiesVersionsResponse) bool {
			return idx == 0 && exists
		},
		Fetcher: func(context.Context, *azsecrets.ListSecretPropertiesVersionsResponse) (azsecrets.ListSecretPropertiesVersionsResponse, error) {
			if v.versErr != nil {
				return azsecrets.ListSecretPropertiesVersionsResponse{}, v.versErr
			}
			if !exists {
				return azsecrets.ListSecretPropertiesVersionsResponse{}, notFound()
			}
			idx++
			return azsecrets.ListSecretPropertiesVersionsResponse{SecretPropertiesListResult: azsecrets.SecretPropertiesListResult{Value: v.props(name, v.secrets[name])}}, nil
		},
	})
}

func sortedNames(secrets map[string][]*fakeVersion) []string {
	names := make([]string, 0, len(secrets))
	for name := range secrets {
		names = append(names, name)
	}
	for i := 0; i < len(names); i++ {
		for j := i + 1; j < len(names); j++ {
			if names[j] < names[i] {
				names[i], names[j] = names[j], names[i]
			}
		}
	}
	return names
}

// ---------------------------------------------------------------------------
// Contract tests.
// ---------------------------------------------------------------------------

func newProvider(v *fakeVault) provider.SecretProvider {
	return skazure.NewWithClient(v, "")
}

func TestName(t *testing.T) {
	assert.Equal(t, "azure", newProvider(newFakeVault(nil)).Name())
}

func TestCapabilities(t *testing.T) {
	caps := newProvider(newFakeVault(nil)).Capabilities()
	assert.True(t, caps.Write)
	assert.True(t, caps.Versioning)
	assert.True(t, caps.Tagging)
	assert.True(t, caps.AuditLog)
	assert.False(t, caps.Rotation, "rotation is vault-side; skret rotate re-PUTs values itself")
	assert.Equal(t, 25, caps.MaxValueKB)
}

func TestGet(t *testing.T) {
	created := time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)
	updated := time.Date(2026, 9, 2, 9, 0, 0, 0, time.UTC)
	expires := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	v := newFakeVault(map[string][]string{"DB-URL": {"postgres://prod/db"}})
	fv := v.secrets["DB-URL"][0]
	fv.created, fv.updated = created, updated
	fv.tags = map[string]*string{
		"team":              new("platform"),
		"skret-expires-at":  new(expires.Format(time.RFC3339)),
		"skret-description": new("primary database"),
	}

	s, err := newProvider(v).Get(context.Background(), "DB_URL")
	require.NoError(t, err)
	assert.Equal(t, "DB-URL", s.Key, "sanitized Key Vault name")
	assert.Equal(t, "postgres://prod/db", s.Value)
	assert.Equal(t, int64(1), s.Version, "single seeded version folds to its number")
	assert.Equal(t, created, s.Meta.CreatedAt)
	assert.Equal(t, updated, s.Meta.UpdatedAt)
	assert.Equal(t, "platform", s.Meta.Tags["team"])
	assert.Equal(t, "primary database", s.Meta.Description)
	assert.Equal(t, expires.UTC(), s.Meta.ExpiresAt)
}

func TestGet_NotFound(t *testing.T) {
	_, err := newProvider(newFakeVault(nil)).Get(context.Background(), "NOPE")
	assert.ErrorIs(t, err, provider.ErrNotFound)
}

func TestGet_TransportErrorIsNotNotFound(t *testing.T) {
	v := newFakeVault(map[string][]string{"DB-URL": {"x"}})
	v.getErr = errors.New("connection reset")
	_, err := newProvider(v).Get(context.Background(), "DB-URL")
	require.Error(t, err)
	assert.NotErrorIs(t, err, provider.ErrNotFound)
	assert.Contains(t, err.Error(), `azure: get "DB-URL"`)
}

func TestGet_UnderscoreKeyReadsSanitizedName(t *testing.T) {
	v := newFakeVault(map[string][]string{"DB-URL": {"x"}})
	s, err := newProvider(v).Get(context.Background(), "DB_URL")
	require.NoError(t, err)
	assert.Equal(t, "DB-URL", s.Key)
}

func TestGet_ImpossibleKeyIsNotFound(t *testing.T) {
	_, err := newProvider(newFakeVault(nil)).Get(context.Background(), "###")
	assert.ErrorIs(t, err, provider.ErrNotFound)
}

func TestGetVersion(t *testing.T) {
	v := newFakeVault(map[string][]string{"API-KEY": {"v1-value", "v2-value"}})
	p := newProvider(v)

	reader, ok := p.(provider.VersionedReader)
	require.True(t, ok)

	s, err := reader.GetVersion(context.Background(), "API-KEY", 1)
	require.NoError(t, err)
	assert.Equal(t, int64(1), s.Version, "must return exactly the requested number")
	assert.Equal(t, "v1-value", s.Value)

	s, err = reader.GetVersion(context.Background(), "API-KEY", 2)
	require.NoError(t, err)
	assert.Equal(t, int64(2), s.Version)
	assert.Equal(t, "v2-value", s.Value)

	_, err = reader.GetVersion(context.Background(), "API-KEY", 3)
	assert.ErrorIs(t, err, provider.ErrNotFound)

	_, err = reader.GetVersion(context.Background(), "API-KEY", 0)
	assert.ErrorIs(t, err, provider.ErrNotFound)
}

func TestGetBatch(t *testing.T) {
	v := newFakeVault(map[string][]string{"A-KEY": {"va"}, "B-KEY": {"vb"}})
	got, err := newProvider(v).GetBatch(context.Background(), []string{"A-KEY", "MISSING", "B-KEY"})
	require.NoError(t, err)
	require.Len(t, got, 2, "missing keys are skipped, matching the AWS provider")
	assert.Equal(t, "A-KEY", got[0].Key)
	assert.Equal(t, "B-KEY", got[1].Key)

	got, err = newProvider(v).GetBatch(context.Background(), nil)
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestList_FiltersByPrefixAndSkipsManaged(t *testing.T) {
	v := newFakeVault(map[string][]string{
		"app-prod-A":   {"va"},
		"app-prod-B":   {"vb"},
		"other-C":      {"vc"},
		"managed-cert": {"cert"},
	})
	got, err := newProvider(v).List(context.Background(), "")
	require.NoError(t, err)
	require.Len(t, got, 3, "managed (certificate-backed) secrets are never surfaced")
	assert.Equal(t, "va", got[0].Value, "List decrypts values like the AWS provider")

	got, err = newProvider(v).List(context.Background(), "/app-prod/")
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "app-prod-A", got[0].Key)
	assert.Equal(t, "app-prod-B", got[1].Key)
}

func TestList_Error(t *testing.T) {
	v := newFakeVault(nil)
	v.listErr = errors.New("boom")
	_, err := newProvider(v).List(context.Background(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "azure: list")
}

func TestListNames(t *testing.T) {
	v := newFakeVault(map[string][]string{"A-KEY": {"va"}, "B-KEY": {"vb"}})
	p := newProvider(v)

	names, err := p.ListNames(context.Background(), "")
	require.NoError(t, err)
	assert.Equal(t, []string{"A-KEY", "B-KEY"}, names)

	names, err = p.ListNames(context.Background(), "B-")
	require.NoError(t, err)
	assert.Equal(t, []string{"B-KEY"}, names)

	assert.Zero(t, v.getCalls, "ListNames must never read secret values")
}

func TestFingerprint(t *testing.T) {
	v := newFakeVault(map[string][]string{"A-KEY": {"va", "v2a"}, "B-KEY": {"vb"}})
	p := newProvider(v)

	fp1, err := p.Fingerprint(context.Background(), "")
	require.NoError(t, err)
	assert.NotEmpty(t, fp1)

	fp2, err := p.Fingerprint(context.Background(), "")
	require.NoError(t, err)
	assert.Equal(t, fp1, fp2, "fingerprint is stable across calls")

	assert.Zero(t, v.getCalls, "fingerprint must not decrypt values")

	// Version bumps must change the fingerprint (watch detection).
	err = p.Set(context.Background(), "A-KEY", "new-value", provider.SecretMeta{})
	require.NoError(t, err)
	fp3, err := p.Fingerprint(context.Background(), "")
	require.NoError(t, err)
	assert.NotEqual(t, fp1, fp3)
}

func TestSet_NewSecretCarriesValueAndMeta(t *testing.T) {
	v := newFakeVault(nil)
	expires := time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)
	err := newProvider(v).Set(context.Background(), "DB_URL", "pg://x", provider.SecretMeta{
		Description: "primary db",
		ExpiresAt:   expires,
		Tags:        map[string]string{"team": "platform"},
	})
	require.NoError(t, err)

	require.Len(t, v.setInputs, 1)
	params := v.setInputs[0]
	assert.Equal(t, "pg://x", *params.Value)
	require.NotNil(t, params.ContentType)
	assert.Equal(t, "text/plain; charset=utf-8", *params.ContentType)
	assert.Equal(t, "platform", *params.Tags["team"])
	assert.Equal(t, expires.UTC().Format(time.RFC3339), *params.Tags[skazure.TagExpiresAt])
	assert.Equal(t, "primary db", *params.Tags[skazure.TagDescription])

	// The stored name is sanitized.
	assert.Contains(t, v.secrets, "DB-URL")
}

func TestSet_ExpiresAtWinsOverUserTag(t *testing.T) {
	v := newFakeVault(nil)
	expires := time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)
	err := newProvider(v).Set(context.Background(), "K", "v", provider.SecretMeta{
		ExpiresAt: expires,
		Tags:      map[string]string{skazure.TagExpiresAt: "1999-01-01T00:00:00Z"},
	})
	require.NoError(t, err)
	assert.Equal(t, expires.UTC().Format(time.RFC3339), *v.setInputs[0].Tags[skazure.TagExpiresAt])
}

func TestSet_ZeroExpiresAtDropsStaleTag(t *testing.T) {
	v := newFakeVault(nil)
	err := newProvider(v).Set(context.Background(), "K", "v", provider.SecretMeta{
		Tags: map[string]string{skazure.TagExpiresAt: "1999-01-01T00:00:00Z"},
	})
	require.NoError(t, err)
	_, has := v.setInputs[0].Tags[skazure.TagExpiresAt]
	assert.False(t, has, "a zero ExpiresAt must not echo a stale reserved tag")
}

func TestSet_InvalidKeyFails(t *testing.T) {
	err := newProvider(newFakeVault(nil)).Set(context.Background(), "---", "v", provider.SecretMeta{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty Azure Key Vault name")
	assert.NotErrorIs(t, err, provider.ErrNotFound)
}

func TestSet_DefiniteRejectIsNotPartialCommit(t *testing.T) {
	v := newFakeVault(nil)
	v.setErr = &azcore.ResponseError{ErrorCode: "BadRequest", StatusCode: 400}
	err := newProvider(v).Set(context.Background(), "K", "v", provider.SecretMeta{})
	require.Error(t, err)
	assert.NotErrorIs(t, err, provider.ErrPartialCommit)
	assert.Contains(t, err.Error(), `azure: set "K"`)
}

func TestSet_AmbiguousErrorThenReadbackProvesCommit(t *testing.T) {
	v := newFakeVault(map[string][]string{"K": {"old"}})
	v.setErr = &azcore.ResponseError{ErrorCode: "InternalServerError", StatusCode: 500}

	// The retrying pipeline committed before the error surfaced: the
	// readback finds the new value, so the write reports success.
	err := newProvider(v).Set(context.Background(), "K", "committed", provider.SecretMeta{})
	assert.NoError(t, err)
	assert.Equal(t, "committed", v.secrets["K"][0].value)
}

func TestSet_AmbiguousErrorThenUnknownOutcome(t *testing.T) {
	v := newFakeVault(map[string][]string{"K": {"old"}})
	v.setErr = errors.New("connection reset")
	v.readbackErr = errors.New("readback also failed")

	err := newProvider(v).Set(context.Background(), "K", "v", provider.SecretMeta{})
	require.ErrorIs(t, err, provider.ErrPartialCommit)
	var pce *provider.PartialCommitError
	require.True(t, errors.As(err, &pce))
	assert.Equal(t, provider.MutationCommitUnknown, pce.CommitState)
	assert.Equal(t, int64(1), pce.PreVersion)
}

func TestSet_AmbiguousErrorButNoCommit(t *testing.T) {
	v := newFakeVault(map[string][]string{"K": {"old"}})
	v.setErr = errors.New("connection reset")
	// The readback still returns the pre-write version: nothing committed,
	// so the original error stands.
	v.readbackVersion = &fakeVersion{
		id:    fakeVaultURL + "/secrets/K/" + hexVersion(1),
		value: "old",
	}

	err := newProvider(v).Set(context.Background(), "K", "v", provider.SecretMeta{})
	require.Error(t, err)
	assert.NotErrorIs(t, err, provider.ErrPartialCommit)
	assert.Contains(t, err.Error(), "connection reset")
}

func TestSet_AmbiguousErrorForeignVersion(t *testing.T) {
	v := newFakeVault(map[string][]string{"K": {"old"}})
	v.setErr = errors.New("connection reset")
	// Simulate another writer winning the race while the write was in
	// flight: what the readback sees is a NEW version with different
	// content, so the outcome cannot be claimed as ours.
	v.readbackVersion = &fakeVersion{
		id:    fakeVaultURL + "/secrets/K/" + hexVersion(99),
		value: "someone-elses",
	}

	err := newProvider(v).Set(context.Background(), "K", "mine", provider.SecretMeta{})
	require.ErrorIs(t, err, provider.ErrPartialCommit)
	var pce *provider.PartialCommitError
	require.True(t, errors.As(err, &pce))
	assert.Equal(t, int64(99), pce.ObservedVersion)
	assert.NotEqual(t, provider.MutationCommitUnknown, pce.CommitState)
}

func TestDelete(t *testing.T) {
	v := newFakeVault(map[string][]string{"K": {"v"}})
	require.NoError(t, newProvider(v).Delete(context.Background(), "K"))
	assert.Empty(t, v.secrets["K"])

	err := newProvider(v).Delete(context.Background(), "K")
	assert.ErrorIs(t, err, provider.ErrNotFound, "second delete reports not found")
}

func TestGetHistory_Ascending(t *testing.T) {
	v := newFakeVault(map[string][]string{"K": {"v1", "v2", "v3"}})
	history, err := newProvider(v).GetHistory(context.Background(), "K")
	require.NoError(t, err)
	require.Len(t, history, 3)
	for i, want := range []string{"v1", "v2", "v3"} {
		assert.Equal(t, int64(i+1), history[i].Version, "oldest first, matching the AWS provider")
		assert.Equal(t, want, history[i].Value)
	}

	_, err = newProvider(v).GetHistory(context.Background(), "MISSING")
	assert.ErrorIs(t, err, provider.ErrNotFound)
}

func TestRollback(t *testing.T) {
	v := newFakeVault(map[string][]string{"K": {"v1", "v2", "v3"}})
	p := newProvider(v)

	require.NoError(t, p.Rollback(context.Background(), "K", 1))

	latest, err := p.Get(context.Background(), "K")
	require.NoError(t, err)
	assert.Equal(t, "v1", latest.Value)
	assert.Greater(t, latest.Version, int64(3), "rollback writes a new version")

	err = p.Rollback(context.Background(), "K", 99)
	assert.ErrorIs(t, err, provider.ErrNotFound)
}

func TestClose(t *testing.T) {
	assert.NoError(t, newProvider(newFakeVault(nil)).Close())
}

// ensure the seeded hex-version helper agrees with strconv for the first 15
// characters (the fold window versionNumber uses).
func TestHexVersionShape(t *testing.T) {
	h := hexVersion(7)
	assert.Len(t, h, 32)
	n, err := strconv.ParseUint(h[:15], 16, 64)
	require.NoError(t, err)
	assert.Equal(t, uint64(7), n)
}

func TestListNames_Error(t *testing.T) {
	v := newFakeVault(nil)
	v.listErr = errors.New("boom")
	_, err := newProvider(v).ListNames(context.Background(), "")
	require.Error(t, err)
}

func TestFingerprint_Error(t *testing.T) {
	v := newFakeVault(nil)
	v.listErr = errors.New("boom")
	_, err := newProvider(v).Fingerprint(context.Background(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "azure: fingerprint")
}

func TestGetHistory_Error(t *testing.T) {
	v := newFakeVault(map[string][]string{"K": {"v"}})
	v.versErr = errors.New("boom")
	_, err := newProvider(v).GetHistory(context.Background(), "K")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "azure: history")

	// A value read failing mid-history surfaces too.
	v2 := newFakeVault(map[string][]string{"K": {"v1", "v2"}})
	v2.getErr = errors.New("boom")
	_, err = newProvider(v2).GetHistory(context.Background(), "K")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "azure: history")
}

func TestDelete_TransportError(t *testing.T) {
	v := newFakeVault(map[string][]string{"K": {"v"}})
	v.delErr = errors.New("boom")
	err := newProvider(v).Delete(context.Background(), "K")
	require.Error(t, err)
	assert.NotErrorIs(t, err, provider.ErrNotFound)
	assert.Contains(t, err.Error(), "azure: delete")
}

func TestNew_FactoryBuildsProviderFromConfig(t *testing.T) {
	// The DefaultAzureCredential chain constructs offline; no token call
	// happens until an operation runs, so this stays a unit test.
	p, err := skazure.New(&config.ResolvedConfig{Provider: "azure", VaultName: "somevault"})
	require.NoError(t, err)
	assert.Equal(t, "azure", p.Name())

	_, err = skazure.New(&config.ResolvedConfig{Provider: "azure"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "one of vault_url or vault_name is required")
}

func TestRollback_ErrorPropagates(t *testing.T) {
	v := newFakeVault(map[string][]string{"K": {"v"}})
	v.versErr = errors.New("boom")
	err := newProvider(v).Rollback(context.Background(), "K", 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "azure: history")
}
