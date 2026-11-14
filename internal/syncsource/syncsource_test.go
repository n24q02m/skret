package syncsource

import (
	"context"
	"errors"
	"testing"

	"github.com/n24q02m/skret/internal/provider"
	"github.com/n24q02m/skret/internal/syncer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeLister serves a fixed key set per path and records every List call,
// unlike the local provider, which ignores the path argument.
type fakeLister struct {
	data  map[string][]string
	fail  map[string]error
	calls []string
}

func (f *fakeLister) List(_ context.Context, path string) ([]*provider.Secret, error) {
	f.calls = append(f.calls, path)
	if err := f.fail[path]; err != nil {
		return nil, err
	}
	out := make([]*provider.Secret, 0, len(f.data[path]))
	for _, name := range f.data[path] {
		out = append(out, &provider.Secret{Key: path + "/" + name, Value: "v-" + name})
	}
	return out, nil
}

func keysOf(secrets []*provider.Secret) []string {
	out := make([]string, 0, len(secrets))
	for _, s := range secrets {
		out = append(out, s.Key)
	}
	return out
}

func TestCollect_NoSourcesUsesEnvPathAndGlobalExclude(t *testing.T) {
	l := &fakeLister{data: map[string][]string{"/app/prod": {"A", "B", "SKIP"}}}
	c := NewCollector(l, "/app/prod", []string{"skip"})

	set, err := c.Collect(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"/app/prod/A", "/app/prod/B"}, keysOf(set.Secrets))
	assert.Equal(t, []string{"/app/prod"}, set.Paths)
	assert.Empty(t, set.Empty)
	assert.Equal(t, "/app/prod", set.Identity())
}

func TestCollect_UnionKeysExcludeAndDefaultPath(t *testing.T) {
	l := &fakeLister{data: map[string][]string{
		"/app/prod": {"CI_APP_KEY", "CREDENTIAL_SECRET", "DOCKERHUB_TOKEN"},
		"/ci/prod":  {"TAP_GITHUB_TOKEN", "CARGO_REGISTRY_TOKEN", "OTHER"},
		"/cf/prod":  {"CF_DEPLOY_TOKEN", "CF_ADMIN", "GLOBAL_SKIP"},
	}}
	c := NewCollector(l, "/app/prod", []string{"GLOBAL_SKIP"})

	set, err := c.Collect(context.Background(), []syncer.SourceSpec{
		{Exclude: []string{"credential_secret"}},
		{Path: "/ci/prod", Keys: []string{"tap_github_token", "CARGO_REGISTRY_TOKEN"}},
		{Path: "/cf/prod/", Exclude: []string{"CF_ADMIN"}},
	})
	require.NoError(t, err)
	assert.Equal(t, []string{
		"/app/prod/CI_APP_KEY", "/app/prod/DOCKERHUB_TOKEN",
		"/ci/prod/TAP_GITHUB_TOKEN", "/ci/prod/CARGO_REGISTRY_TOKEN",
		"/cf/prod/CF_DEPLOY_TOKEN",
	}, keysOf(set.Secrets))
	assert.Equal(t, []string{"/app/prod", "/ci/prod", "/cf/prod"}, set.Paths)
	assert.Equal(t, "/app/prod,/ci/prod,/cf/prod", set.Identity())
	assert.Empty(t, set.Empty)
}

func TestCollect_ListsEachPathOnceAcrossTargets(t *testing.T) {
	l := &fakeLister{data: map[string][]string{
		"/app/prod": {"A"},
		"/ci/prod":  {"TAP"},
	}}
	c := NewCollector(l, "/app/prod", nil)

	_, err := c.Collect(context.Background(), []syncer.SourceSpec{{}, {Path: "/ci/prod", Keys: []string{"TAP"}}})
	require.NoError(t, err)
	_, err = c.Collect(context.Background(), nil)
	require.NoError(t, err)
	_, err = c.Collect(context.Background(), []syncer.SourceSpec{{Path: "/ci/prod"}})
	require.NoError(t, err)
	assert.Equal(t, []string{"/app/prod", "/ci/prod"}, l.calls)
}

func TestCollect_FilteringDoesNotLeakIntoCachedListing(t *testing.T) {
	l := &fakeLister{data: map[string][]string{"/ci/prod": {"A", "B"}}}
	c := NewCollector(l, "/app/prod", nil)

	first, err := c.Collect(context.Background(), []syncer.SourceSpec{{Path: "/ci/prod", Keys: []string{"A"}}})
	require.NoError(t, err)
	assert.Equal(t, []string{"/ci/prod/A"}, keysOf(first.Secrets))
	second, err := c.Collect(context.Background(), []syncer.SourceSpec{{Path: "/ci/prod"}})
	require.NoError(t, err)
	assert.Equal(t, []string{"/ci/prod/A", "/ci/prod/B"}, keysOf(second.Secrets))
}

func TestCollect_DuplicateNamesAcrossSourcesListsEveryName(t *testing.T) {
	l := &fakeLister{data: map[string][]string{
		"/a": {"ZED", "SHARED", "ONLY_A", "ALPHA"},
		"/b": {"SHARED", "ALPHA", "ONLY_B", "ZED"},
	}}
	c := NewCollector(l, "/a", nil)

	_, err := c.Collect(context.Background(), []syncer.SourceSpec{{}, {Path: "/b"}})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidSources)
	assert.Contains(t, err.Error(), "ALPHA, SHARED, ZED")
	assert.NotContains(t, err.Error(), "ONLY_")
}

func TestCollect_MissingDeclaredKeysIsInvalid(t *testing.T) {
	l := &fakeLister{data: map[string][]string{"/ci/prod": {"A", "SKIP"}}}
	c := NewCollector(l, "/app/prod", []string{"SKIP"})

	_, err := c.Collect(context.Background(), []syncer.SourceSpec{{Path: "/ci/prod", Keys: []string{"Z", "A", "SKIP", "M"}}})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidSources)
	assert.Contains(t, err.Error(), `"/ci/prod"`)
	assert.Contains(t, err.Error(), "M, SKIP, Z")
}

func TestCollect_ReportsEverySourceThatIsEmpty(t *testing.T) {
	l := &fakeLister{data: map[string][]string{
		"/app/prod": {},
		"/ci/prod":  {"A"},
		"/cf/prod":  {"ONLY"},
	}}
	c := NewCollector(l, "/app/prod", nil)

	set, err := c.Collect(context.Background(), []syncer.SourceSpec{
		{},
		{Path: "/ci/prod"},
		{Path: "/cf/prod", Exclude: []string{"ONLY"}},
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"/ci/prod/A"}, keysOf(set.Secrets))
	assert.Equal(t, []string{"/app/prod", "/cf/prod"}, set.Empty)
}

func TestCollect_ListErrorNamesThePath(t *testing.T) {
	boom := errors.New("access denied")
	l := &fakeLister{
		data: map[string][]string{"/app/prod": {"A"}},
		fail: map[string]error{"/ci/prod": boom},
	}
	c := NewCollector(l, "/app/prod", nil)

	_, err := c.Collect(context.Background(), []syncer.SourceSpec{{}, {Path: "/ci/prod"}})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrList)
	assert.ErrorIs(t, err, boom)
	assert.NotErrorIs(t, err, ErrInvalidSources)
	assert.Contains(t, err.Error(), `"/ci/prod"`)

	// A failed listing is not cached as an empty one.
	_, err = c.Collect(context.Background(), []syncer.SourceSpec{{Path: "/ci/prod"}})
	require.ErrorIs(t, err, boom)
}

func TestCollect_DuplicatePathAfterDefaultingIsInvalid(t *testing.T) {
	l := &fakeLister{data: map[string][]string{"/app/prod": {"A"}}}
	c := NewCollector(l, "/app/prod", nil)

	_, err := c.Collect(context.Background(), []syncer.SourceSpec{{}, {Path: "/app/prod/"}})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidSources)
	assert.Contains(t, err.Error(), `"/app/prod"`)
	assert.Empty(t, l.calls, "invalid declarations fail before any provider call")
}

func TestCollect_RootPathKeepsItsSlash(t *testing.T) {
	l := &fakeLister{data: map[string][]string{"/": {"A"}}}
	c := NewCollector(l, "/app/prod", nil)

	set, err := c.Collect(context.Background(), []syncer.SourceSpec{{Path: "/"}})
	require.NoError(t, err)
	assert.Equal(t, []string{"/"}, set.Paths)
	assert.Equal(t, []string{"/"}, l.calls)
}
