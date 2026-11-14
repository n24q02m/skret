package cli

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/n24q02m/skret/internal/syncer"
	"github.com/n24q02m/skret/internal/syncsource"
	"github.com/n24q02m/skret/pkg/skret"
)

// The local provider ignores the path it is asked to list, so every source
// below sees the same file; keys/exclude carve it into distinct sources.
// Path semantics proper are covered in internal/syncsource.

func withGithubSourcesTarget(t *testing.T, dir, baseURL, sources string) {
	t.Helper()
	appendSyncTarget(t, dir, fmt.Sprintf(`sync:
  targets:
    - type: github
      repo: o/r
      base_url: %s
      sources:
%s`, baseURL, sources))
}

func requireExit(t *testing.T, err error, code int) {
	t.Helper()
	require.Error(t, err)
	var se *skret.Error
	require.True(t, errors.As(err, &se), "want *skret.Error, got %T: %v", err, err)
	assert.Equal(t, code, se.Code, "error: %v", err)
}

func TestSyncSources_KeysFilterBeforePush(t *testing.T) {
	isolateSyncHome(t)
	pt, srv := newPruneTarget(t, map[string]string{}, http.StatusNoContent)
	dir := setupSyncRepoWithSecrets(t, map[string]string{"CI_APP_KEY": "1", "CREDENTIAL_SECRET": "2", "TAP": "3"})
	withGithubSourcesTarget(t, dir, srv.URL, `        - keys: [CI_APP_KEY]
        - path: /ci/prod
          keys: [TAP]
`)
	t.Setenv("GITHUB_TOKEN", "tok")

	out := runSyncCmd(t, dir, []string{"--dry-run"})
	assert.Contains(t, out, "[dry-run] github: would write 2 secret(s): CI_APP_KEY, TAP")

	runSyncCmd(t, dir, nil)
	assert.ElementsMatch(t, []string{"CI_APP_KEY", "TAP"}, pt.puts)
	assert.NotContains(t, pt.puts, "CREDENTIAL_SECRET", "a runtime secret outside keys is never pushed")
}

func TestSyncSources_PruneAgainstUnion(t *testing.T) {
	isolateSyncHome(t)
	pt, srv := newPruneTarget(t, map[string]string{
		"CI_APP_KEY":        "2026-01-01T00:00:00Z",
		"TAP":               "2026-01-01T00:00:00Z",
		"CREDENTIAL_SECRET": "2026-02-01T00:00:00Z",
		"OC_MODEL":          "2026-03-01T00:00:00Z",
	}, http.StatusNoContent)
	dir := setupSyncRepoWithSecrets(t, map[string]string{"CI_APP_KEY": "1", "CREDENTIAL_SECRET": "2", "TAP": "3"})
	withGithubSourcesTarget(t, dir, srv.URL, `        - keys: [CI_APP_KEY]
        - path: /ci/prod
          keys: [TAP]
`)
	t.Setenv("GITHUB_TOKEN", "tok")

	out := runSyncCmd(t, dir, []string{"--dry-run", "--prune"})
	assert.Contains(t, out, "would delete: CREDENTIAL_SECRET")
	assert.Contains(t, out, "would delete: OC_MODEL")
	assert.NotContains(t, out, "would delete: TAP")
	assert.NotContains(t, out, "would delete: CI_APP_KEY")
	assert.Empty(t, pt.deletes)

	out = runSyncCmd(t, dir, []string{"--prune", "--format", "json"})
	assert.ElementsMatch(t, []string{"CREDENTIAL_SECRET", "OC_MODEL"}, pt.deletes)
	// The local test environment has no path, so the default source is "".
	assert.Contains(t, out, `"source": ",/ci/prod"`)
}

func TestSyncSources_DuplicateNamesExitConfigBeforeAnyRequest(t *testing.T) {
	isolateSyncHome(t)
	pt, srv := newPruneTarget(t, map[string]string{}, http.StatusNoContent)
	dir := setupSyncRepoWithSecrets(t, map[string]string{"BETA": "1", "ALPHA": "2"})
	withGithubSourcesTarget(t, dir, srv.URL, `        - {}
        - path: /ci/prod
`)
	t.Setenv("GITHUB_TOKEN", "tok")

	err := runSyncCmdErr(t, dir, nil)
	requireExit(t, err, skret.ExitConfigError)
	assert.ErrorIs(t, err, syncsource.ErrInvalidSources)
	assert.Contains(t, err.Error(), "ALPHA, BETA")
	assert.Zero(t, pt.requests)
}

func TestSyncSources_MissingDeclaredKeyExitConfig(t *testing.T) {
	isolateSyncHome(t)
	pt, srv := newPruneTarget(t, map[string]string{}, http.StatusNoContent)
	dir := setupSyncRepoWithSecrets(t, map[string]string{"ALPHA": "1"})
	withGithubSourcesTarget(t, dir, srv.URL, `        - path: /ci/prod
          keys: [ALPHA, CARGO_REGISTRY_TOKEN]
`)
	t.Setenv("GITHUB_TOKEN", "tok")

	err := runSyncCmdErr(t, dir, []string{"--dry-run"})
	requireExit(t, err, skret.ExitConfigError)
	assert.Contains(t, err.Error(), "CARGO_REGISTRY_TOKEN")
	assert.Zero(t, pt.requests)
}

func TestSyncSources_PruneRefusesAnyEmptySource(t *testing.T) {
	isolateSyncHome(t)
	pt, srv := newPruneTarget(t, map[string]string{"ORPHAN": "2026-07-17T00:00:00Z"}, http.StatusNoContent)
	dir := setupSyncRepoWithSecrets(t, map[string]string{"ALPHA": "1", "BETA": "2"})
	// The union is not empty, but the second source is.
	withGithubSourcesTarget(t, dir, srv.URL, `        - keys: [ALPHA]
        - path: /ci/prod
          exclude: [ALPHA, BETA]
`)
	t.Setenv("GITHUB_TOKEN", "tok")

	for _, args := range [][]string{{"--prune"}, {"--prune", "--dry-run"}} {
		err := runSyncCmdErr(t, dir, args)
		requireExit(t, err, skret.ExitConfigError)
		assert.ErrorIs(t, err, syncer.ErrPruneEmptySource)
		assert.Contains(t, err.Error(), `"/ci/prod"`)
	}
	assert.Zero(t, pt.requests, "an empty source must stop before any target request")

	// Without --prune an empty source only contributes nothing.
	runSyncCmd(t, dir, nil)
	assert.Equal(t, []string{"ALPHA"}, pt.puts)
	assert.Empty(t, pt.deletes)
}

func TestSyncSources_EveryTargetResolvedBeforeAnyWrite(t *testing.T) {
	isolateSyncHome(t)
	first, srv1 := newPruneTarget(t, map[string]string{}, http.StatusNoContent)
	second, srv2 := newPruneTarget(t, map[string]string{}, http.StatusNoContent)
	dir := setupSyncRepoWithSecrets(t, map[string]string{"ALPHA": "1"})
	appendSyncTarget(t, dir, fmt.Sprintf(`sync:
  targets:
    - type: github
      repo: o/one
      base_url: %s
    - type: github
      repo: o/two
      base_url: %s
      sources:
        - path: /ci/prod
          keys: [MISSING]
`, srv1.URL, srv2.URL))
	t.Setenv("GITHUB_TOKEN", "tok")

	err := runSyncCmdErr(t, dir, nil)
	requireExit(t, err, skret.ExitConfigError)
	assert.Zero(t, first.requests, "the valid first target is not written when a later target is invalid")
	assert.Zero(t, second.requests)
}

func TestSyncSources_TopLevelExcludeAppliesToSources(t *testing.T) {
	isolateSyncHome(t)
	pt, srv := newPruneTarget(t, map[string]string{}, http.StatusNoContent)
	dir := setupSyncRepoWithSecrets(t, map[string]string{"ALPHA": "1", "BETA": "2"})
	appendSyncTarget(t, dir, "exclude: [BETA]\n")
	withGithubSourcesTarget(t, dir, srv.URL, `        - path: /ci/prod
          keys: [BETA]
`)
	t.Setenv("GITHUB_TOKEN", "tok")

	err := runSyncCmdErr(t, dir, nil)
	requireExit(t, err, skret.ExitConfigError)
	assert.Contains(t, err.Error(), "BETA")
	assert.Zero(t, pt.requests)
}

func TestSyncSources_TargetWithoutSourcesKeepsEnvPath(t *testing.T) {
	isolateSyncHome(t)
	first, srv1 := newPruneTarget(t, map[string]string{}, http.StatusNoContent)
	second, srv2 := newPruneTarget(t, map[string]string{}, http.StatusNoContent)
	dir := setupSyncRepoWithSecrets(t, map[string]string{"ALPHA": "1", "BETA": "2"})
	appendSyncTarget(t, dir, fmt.Sprintf(`sync:
  targets:
    - type: github
      repo: o/one
      base_url: %s
    - type: github
      repo: o/two
      base_url: %s
      sources:
        - path: /ci/prod
          keys: [BETA]
`, srv1.URL, srv2.URL))
	t.Setenv("GITHUB_TOKEN", "tok")

	runSyncCmd(t, dir, nil)
	assert.ElementsMatch(t, []string{"ALPHA", "BETA"}, first.puts)
	assert.Equal(t, []string{"BETA"}, second.puts)
}

func TestSourceSetError_MapsExitCodes(t *testing.T) {
	listErr := fmt.Errorf("%w: %q: %w", syncsource.ErrList, "/ci/prod", errors.New("denied"))
	requireExit(t, sourceSetError(listErr), skret.ExitProviderError)

	invalid := fmt.Errorf("%w: duplicate", syncsource.ErrInvalidSources)
	requireExit(t, sourceSetError(invalid), skret.ExitConfigError)
}
