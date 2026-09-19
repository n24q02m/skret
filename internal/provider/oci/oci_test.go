package oci

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/secrets"
	"github.com/oracle/oci-go-sdk/v65/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/n24q02m/skret/internal/config"
	"github.com/n24q02m/skret/internal/provider"
)

// mockServiceError implements common.ServiceError for error-class fixtures.
type mockServiceError struct {
	status int
	code   string
	msg    string
}

func (e *mockServiceError) GetHTTPStatusCode() int  { return e.status }
func (e *mockServiceError) GetCode() string         { return e.code }
func (e *mockServiceError) GetMessage() string      { return e.msg }
func (e *mockServiceError) GetOpcRequestID() string { return "" }
func (e *mockServiceError) Error() string           { return fmt.Sprintf("%s (HTTP %d)", e.msg, e.status) }

// mockSecretsClient records GetSecretBundleByName calls.
type mockSecretsClient struct {
	byName    map[string]secrets.SecretBundle
	byVersion map[string]map[int64]secrets.SecretBundle
	errGet    error
	calls     []string
}

func (m *mockSecretsClient) GetSecretBundleByName(_ context.Context, request secrets.GetSecretBundleByNameRequest) (secrets.GetSecretBundleByNameResponse, error) {
	name := derefString(request.SecretName)
	m.calls = append(m.calls, fmt.Sprintf("GetSecretBundleByName:%s@%d", name, derefInt64(request.VersionNumber)))
	if m.errGet != nil {
		return secrets.GetSecretBundleByNameResponse{}, m.errGet
	}
	if request.VersionNumber != nil {
		if versions, ok := m.byVersion[name]; ok {
			if bundle, ok := versions[*request.VersionNumber]; ok {
				return secrets.GetSecretBundleByNameResponse{SecretBundle: bundle}, nil
			}
		}
		return secrets.GetSecretBundleByNameResponse{}, &mockServiceError{status: 404, code: "NotAuthorizedOrNotFound", msg: "not found"}
	}
	if bundle, ok := m.byName[name]; ok {
		return secrets.GetSecretBundleByNameResponse{SecretBundle: bundle}, nil
	}
	return secrets.GetSecretBundleByNameResponse{}, &mockServiceError{status: 404, code: "NotAuthorizedOrNotFound", msg: "not found"}
}

// mockVaultsClient records vault-service calls.
type mockVaultsClient struct {
	summaries      []vault.SecretSummary
	versionsByOCID map[string][]int64
	bundlesByOCID  map[string]map[int64]secrets.SecretBundle

	// pages, when set, serves ListSecrets results one page per call with an
	// OpcNextPage until exhausted (pagination simulation).
	pages     [][]vault.SecretSummary
	listCalls int

	errList     error
	errVersions error
	errCreate   error
	errUpdate   error
	errDelete   error

	// onCreate/onUpdate simulate the service committing the write before a
	// response is lost: they run before the error is returned, so a later
	// readback observes the committed state.
	onCreate func()
	onUpdate func()

	created []vault.CreateSecretRequest
	updated []vault.UpdateSecretRequest
	deleted []vault.ScheduleSecretDeletionRequest
}

func (m *mockVaultsClient) CreateSecret(_ context.Context, request vault.CreateSecretRequest) (vault.CreateSecretResponse, error) {
	if m.onCreate != nil {
		m.onCreate()
	}
	m.created = append(m.created, request)
	if m.errCreate != nil {
		return vault.CreateSecretResponse{}, m.errCreate
	}
	return vault.CreateSecretResponse{}, nil
}

func (m *mockVaultsClient) UpdateSecret(_ context.Context, request vault.UpdateSecretRequest) (vault.UpdateSecretResponse, error) {
	if m.onUpdate != nil {
		m.onUpdate()
	}
	m.updated = append(m.updated, request)
	if m.errUpdate != nil {
		return vault.UpdateSecretResponse{}, m.errUpdate
	}
	return vault.UpdateSecretResponse{}, nil
}

func (m *mockVaultsClient) ListSecrets(_ context.Context, request vault.ListSecretsRequest) (vault.ListSecretsResponse, error) {
	if m.errList != nil {
		return vault.ListSecretsResponse{}, m.errList
	}
	items := m.summaries
	if m.pages != nil {
		page := m.pages[m.listCalls]
		m.listCalls++
		items = page
	}
	if request.Name != nil {
		var filtered []vault.SecretSummary
		for i := range items {
			if derefString(items[i].SecretName) == *request.Name {
				filtered = append(filtered, items[i])
			}
		}
		items = filtered
	}
	resp := vault.ListSecretsResponse{Items: items}
	if m.pages != nil && m.listCalls < len(m.pages) {
		resp.OpcNextPage = common.String("next-page")
	}
	return resp, nil
}

func (m *mockVaultsClient) ListSecretVersions(_ context.Context, request vault.ListSecretVersionsRequest) (vault.ListSecretVersionsResponse, error) {
	if m.errVersions != nil {
		return vault.ListSecretVersionsResponse{}, m.errVersions
	}
	versions := m.versionsByOCID[derefString(request.SecretId)]
	items := make([]vault.SecretVersionSummary, 0, len(versions))
	for _, v := range versions {
		items = append(items, vault.SecretVersionSummary{VersionNumber: common.Int64(v)})
	}
	return vault.ListSecretVersionsResponse{Items: items}, nil
}

func (m *mockVaultsClient) ScheduleSecretDeletion(_ context.Context, request vault.ScheduleSecretDeletionRequest) (vault.ScheduleSecretDeletionResponse, error) {
	m.deleted = append(m.deleted, request)
	if m.errDelete != nil {
		return vault.ScheduleSecretDeletionResponse{}, m.errDelete
	}
	return vault.ScheduleSecretDeletionResponse{}, nil
}

// newTestProvider builds a provider over mocks with one secret already in
// the vault: name myapp-prod_API_KEY under path /myapp/prod.
func newTestProvider() (*Provider, *mockSecretsClient, *mockVaultsClient) {
	secretsMock := &mockSecretsClient{byName: map[string]secrets.SecretBundle{}, byVersion: map[string]map[int64]secrets.SecretBundle{}}
	vaultsMock := &mockVaultsClient{
		versionsByOCID: map[string][]int64{},
		bundlesByOCID:  map[string]map[int64]secrets.SecretBundle{},
	}
	p := NewWithClients(secretsMock, vaultsMock, "/myapp/prod", "ocid1.compartment.oc1..c", "ocid1.vault.oc1..v", "ocid1.key.oc1..k")
	return p, secretsMock, vaultsMock
}

func ociBundle(secretID string, version int64, value string) secrets.SecretBundle {
	return secrets.SecretBundle{
		SecretId:      common.String(secretID),
		VersionNumber: common.Int64(version),
		SecretBundleContent: secrets.Base64SecretBundleContentDetails{
			Content: common.String(base64.StdEncoding.EncodeToString([]byte(value))),
		},
		TimeCreated: &common.SDKTime{Time: time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)},
	}
}

func addSecret(t *testing.T, p *Provider, sm *mockSecretsClient, vm *mockVaultsClient, name string, version int64, value string) {
	t.Helper()
	secretID := "ocid1.secret.oc1.." + name
	bundle := ociBundle(secretID, version, value)
	sm.byName[name] = bundle
	if sm.byVersion[name] == nil {
		sm.byVersion[name] = map[int64]secrets.SecretBundle{}
	}
	sm.byVersion[name][version] = bundle
	vm.versionsByOCID[secretID] = append(vm.versionsByOCID[secretID], version)
	vm.summaries = append(vm.summaries, vault.SecretSummary{
		SecretName:    common.String(name),
		Id:            bundle.SecretId,
		CompartmentId: common.String("ocid1.compartment.oc1..c"),
		VaultId:       common.String("ocid1.vault.oc1..v"),
		TimeCreated:   bundle.TimeCreated,
	})
}

// isolateOCIAuth points HOME/USERPROFILE at an empty temp dir and blanks
// every OCI env var, so auth resolution only sees what the test sets.
func isolateOCIAuth(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	for _, key := range []string{EnvAuth, EnvUser, EnvTenancy, EnvFingerprint, EnvKeyFile, EnvPassPhrase, EnvRegion, EnvProfile, EnvConfigFile} {
		t.Setenv(key, "")
	}
	return home
}

func TestOCIName(t *testing.T) {
	p, _, _ := newTestProvider()
	assert.Equal(t, "oci", p.Name())
}

func TestOCICapabilities(t *testing.T) {
	p, _, _ := newTestProvider()
	caps := p.Capabilities()
	assert.True(t, caps.Write)
	assert.True(t, caps.Versioning)
	assert.True(t, caps.Tagging)
	assert.True(t, caps.AuditLog)
	assert.Equal(t, 25, caps.MaxValueKB)
}

func TestOCIClose(t *testing.T) {
	p, _, _ := newTestProvider()
	assert.NoError(t, p.Close())
}

func TestOCIGet(t *testing.T) {
	p, sm, vm := newTestProvider()
	addSecret(t, p, sm, vm, "myapp-prod_API_KEY", 3, "secret-value")

	s, err := p.Get(context.Background(), "/myapp/prod/API_KEY")
	require.NoError(t, err)
	assert.Equal(t, "/myapp/prod/API_KEY", s.Key)
	assert.Equal(t, "secret-value", s.Value)
	assert.Equal(t, int64(3), s.Version)
	assert.Equal(t, time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC), s.Meta.UpdatedAt)
}

func TestOCIGetNotFound(t *testing.T) {
	p, _, _ := newTestProvider()
	_, err := p.Get(context.Background(), "/myapp/prod/MISSING")
	assert.ErrorIs(t, err, provider.ErrNotFound)
}

func TestOCIGetEmptyKey(t *testing.T) {
	p, _, _ := newTestProvider()
	_, err := p.Get(context.Background(), "")
	assert.ErrorIs(t, err, provider.ErrNotFound)
}

func TestOCIGetInvalidName(t *testing.T) {
	p, _, _ := newTestProvider()
	_, err := p.Get(context.Background(), "/myapp/prod/BAD KEY")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid secret name")
}

func TestOCIGetUnsupportedContent(t *testing.T) {
	p, sm, _ := newTestProvider()
	sm.byName["myapp-prod_API_KEY"] = secrets.SecretBundle{
		SecretId:      common.String("ocid1.secret.oc1..s"),
		VersionNumber: common.Int64(1),
	}
	_, err := p.Get(context.Background(), "/myapp/prod/API_KEY")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no base64 content")
}

func TestOCIGetGenericError(t *testing.T) {
	p, sm, _ := newTestProvider()
	sm.errGet = errors.New("network down")
	_, err := p.Get(context.Background(), "/myapp/prod/API_KEY")
	require.Error(t, err)
	assert.NotErrorIs(t, err, provider.ErrNotFound)
	assert.Contains(t, err.Error(), `oci: get "myapp-prod_API_KEY"`)
}

func TestOCIGetVersion(t *testing.T) {
	p, sm, vm := newTestProvider()
	addSecret(t, p, sm, vm, "myapp-prod_API_KEY", 7, "old-value")

	s, err := p.GetVersion(context.Background(), "/myapp/prod/API_KEY", 7)
	require.NoError(t, err)
	assert.Equal(t, int64(7), s.Version)
	assert.Equal(t, "old-value", s.Value)
}

func TestOCIGetVersionInvalidNumber(t *testing.T) {
	p, _, _ := newTestProvider()
	_, err := p.GetVersion(context.Background(), "/myapp/prod/API_KEY", 0)
	assert.ErrorIs(t, err, provider.ErrNotFound)
}

func TestOCIGetVersionMismatch(t *testing.T) {
	p, sm, vm := newTestProvider()
	addSecret(t, p, sm, vm, "myapp-prod_API_KEY", 7, "old-value")
	// The mock can only serve versions it knows; ask for 7 but make the
	// bundle report a different number to exercise the mismatch guard.
	sm.byVersion["myapp-prod_API_KEY"][7] = ociBundle("ocid1.secret.oc1..myapp-prod_API_KEY", 6, "other")

	_, err := p.GetVersion(context.Background(), "/myapp/prod/API_KEY", 7)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "version mismatch")
}

func TestOCIGetBatch(t *testing.T) {
	p, sm, vm := newTestProvider()
	addSecret(t, p, sm, vm, "myapp-prod_A", 1, "va")
	addSecret(t, p, sm, vm, "myapp-prod_B", 1, "vb")

	got, err := p.GetBatch(context.Background(), []string{"/myapp/prod/A", "/myapp/prod/MISSING", "/myapp/prod/B"})
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "va", got[0].Value)
	assert.Equal(t, "vb", got[1].Value)
}

func TestOCIGetBatchError(t *testing.T) {
	p, sm, _ := newTestProvider()
	sm.errGet = errors.New("boom")
	_, err := p.GetBatch(context.Background(), []string{"/myapp/prod/A"})
	require.Error(t, err)
}

func TestOCIGetBatchEmpty(t *testing.T) {
	p, _, _ := newTestProvider()
	got, err := p.GetBatch(context.Background(), nil)
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestOCIListFiltersByPathAndDecrypts(t *testing.T) {
	p, sm, vm := newTestProvider()
	addSecret(t, p, sm, vm, "myapp-prod_A", 1, "va")
	addSecret(t, p, sm, vm, "other_B", 1, "vb")

	got, err := p.List(context.Background(), "")
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "/myapp/prod/A", got[0].Key)
	assert.Equal(t, "va", got[0].Value)
}

func TestOCIListExplicitPrefix(t *testing.T) {
	p, sm, vm := newTestProvider()
	addSecret(t, p, sm, vm, "myapp-prod_A", 1, "va")
	addSecret(t, p, sm, vm, "other_B", 1, "vb")

	got, err := p.List(context.Background(), "/other")
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "/other/B", got[0].Key)
}

func TestOCIListError(t *testing.T) {
	p, _, vm := newTestProvider()
	vm.errList = &mockServiceError{status: 403, code: "NotAuthorized", msg: "denied"}
	_, err := p.List(context.Background(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "denied")
}

func TestOCIListNamesSkipsDecryption(t *testing.T) {
	p, sm, vm := newTestProvider()
	addSecret(t, p, sm, vm, "myapp-prod_A", 1, "va")
	addSecret(t, p, sm, vm, "other_B", 1, "vb")
	sm.calls = nil

	names, err := p.ListNames(context.Background(), "")
	require.NoError(t, err)
	assert.Equal(t, []string{"/myapp/prod/A"}, names)
	assert.Empty(t, sm.calls, "ListNames must not fetch bundles")
}

func TestOCIListNamesError(t *testing.T) {
	p, _, vm := newTestProvider()
	vm.errList = errors.New("list failed")
	_, err := p.ListNames(context.Background(), "")
	require.Error(t, err)
}

func TestOCIFingerprintVersionSensitive(t *testing.T) {
	p, sm, vm := newTestProvider()
	addSecret(t, p, sm, vm, "myapp-prod_A", 1, "va")

	fp1, err := p.Fingerprint(context.Background(), "")
	require.NoError(t, err)

	addSecret(t, p, sm, vm, "myapp-prod_B", 2, "vb")
	fp2, err := p.Fingerprint(context.Background(), "")
	require.NoError(t, err)
	assert.NotEqual(t, fp1, fp2)
}

func TestOCIFingerprintError(t *testing.T) {
	p, _, vm := newTestProvider()
	vm.errList = errors.New("fingerprint list failed")
	_, err := p.Fingerprint(context.Background(), "")
	require.Error(t, err)
}

func TestOCISetCreatesNewSecret(t *testing.T) {
	p, _, vm := newTestProvider()
	err := p.Set(context.Background(), "/myapp/prod/API_KEY", "new-value", provider.SecretMeta{
		Description: "api key",
		Tags:        map[string]string{"team": "core"},
	})
	require.NoError(t, err)
	require.Len(t, vm.created, 1)
	details := vm.created[0].CreateSecretDetails
	assert.Equal(t, "ocid1.compartment.oc1..c", derefString(details.CompartmentId))
	assert.Equal(t, "ocid1.vault.oc1..v", derefString(details.VaultId))
	assert.Equal(t, "ocid1.key.oc1..k", derefString(details.KeyId))
	assert.Equal(t, "myapp-prod_API_KEY", derefString(details.SecretName))
	assert.Equal(t, "api key", derefString(details.Description))
	raw, decErr := base64.StdEncoding.DecodeString(derefString(details.SecretContent.(*vault.Base64SecretContentDetails).Content))
	require.NoError(t, decErr)
	assert.Equal(t, "new-value", string(raw))
	assert.Equal(t, map[string]string{"team": "core"}, details.FreeformTags)
	assert.Empty(t, vm.updated)
}

func TestOCISetCreateRequiresKeyID(t *testing.T) {
	secretsMock := &mockSecretsClient{byName: map[string]secrets.SecretBundle{}}
	p := NewWithClients(secretsMock, &mockVaultsClient{}, "", "ocid1.compartment.oc1..c", "ocid1.vault.oc1..v", "")
	err := p.Set(context.Background(), "API_KEY", "v", provider.SecretMeta{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "key_id is required")
}

func TestOCISetUpdatesExistingSecret(t *testing.T) {
	p, sm, vm := newTestProvider()
	addSecret(t, p, sm, vm, "myapp-prod_API_KEY", 3, "old-value")

	err := p.Set(context.Background(), "/myapp/prod/API_KEY", "new-value", provider.SecretMeta{})
	require.NoError(t, err)
	require.Len(t, vm.updated, 1)
	assert.Equal(t, "ocid1.secret.oc1..myapp-prod_API_KEY", derefString(vm.updated[0].SecretId))
	raw, decErr := base64.StdEncoding.DecodeString(derefString(vm.updated[0].UpdateSecretDetails.SecretContent.(*vault.Base64SecretContentDetails).Content))
	require.NoError(t, decErr)
	assert.Equal(t, "new-value", string(raw))
	assert.Empty(t, vm.created, "existing secrets must update, not create")
}

func TestOCISetLookupErrorAborts(t *testing.T) {
	p, sm, vm := newTestProvider()
	sm.errGet = errors.New("lookup failed")
	err := p.Set(context.Background(), "/myapp/prod/API_KEY", "v", provider.SecretMeta{})
	require.Error(t, err)
	assert.Empty(t, vm.created)
	assert.Empty(t, vm.updated)
}

func TestOCISetUpdateDefinitiveFailureNoReconcile(t *testing.T) {
	p, sm, vm := newTestProvider()
	addSecret(t, p, sm, vm, "myapp-prod_API_KEY", 3, "old-value")
	vm.errUpdate = &mockServiceError{status: 400, code: "InvalidParameter", msg: "bad request"}

	err := p.Set(context.Background(), "/myapp/prod/API_KEY", "v", provider.SecretMeta{})
	require.Error(t, err)
	var partial *provider.PartialCommitError
	assert.False(t, errors.As(err, &partial))
	assert.Contains(t, err.Error(), "bad request")
}

func TestOCISetUpdateAmbiguousFailureCommitted(t *testing.T) {
	p, sm, vm := newTestProvider()
	addSecret(t, p, sm, vm, "myapp-prod_API_KEY", 3, "old-value")
	vm.errUpdate = &mockServiceError{status: 500, code: "InternalError", msg: "server error"}
	vm.onUpdate = func() {
		// The service committed version 4 before the response was lost.
		sm.byName["myapp-prod_API_KEY"] = ociBundle("ocid1.secret.oc1..myapp-prod_API_KEY", 4, "v")
	}

	err := p.Set(context.Background(), "/myapp/prod/API_KEY", "v", provider.SecretMeta{})
	require.Error(t, err)
	var partial *provider.PartialCommitError
	require.True(t, errors.As(err, &partial))
	assert.Equal(t, provider.MutationCommitUnknown, partial.CommitState)
	assert.Equal(t, int64(3), partial.PreVersion)
	assert.Equal(t, int64(4), partial.ObservedVersion)
}

func TestOCISetUpdateAmbiguousFailureNotCommitted(t *testing.T) {
	p, sm, vm := newTestProvider()
	addSecret(t, p, sm, vm, "myapp-prod_API_KEY", 3, "old-value")
	vm.errUpdate = &mockServiceError{status: 429, code: "TooManyRequests", msg: "throttled"}

	err := p.Set(context.Background(), "/myapp/prod/API_KEY", "v", provider.SecretMeta{})
	require.Error(t, err)
	var partial *provider.PartialCommitError
	assert.False(t, errors.As(err, &partial))
	assert.Contains(t, err.Error(), "throttled")
}

func TestOCISetCreateAmbiguousFailureCommitted(t *testing.T) {
	p, sm, vm := newTestProvider()
	vm.errCreate = &mockServiceError{status: 500, code: "InternalError", msg: "server error"}
	vm.onCreate = func() {
		// The service created the secret before the response was lost, so
		// the post-failure readback finds version 1.
		sm.byName["myapp-prod_API_KEY"] = ociBundle("ocid1.secret.oc1..myapp-prod_API_KEY", 1, "v")
	}

	err := p.Set(context.Background(), "/myapp/prod/API_KEY", "v", provider.SecretMeta{})
	require.Error(t, err)
	var partial *provider.PartialCommitError
	require.True(t, errors.As(err, &partial))
	assert.Equal(t, provider.MutationCommitUnknown, partial.CommitState)
	assert.Equal(t, int64(1), partial.ObservedVersion)
}

func TestOCISetCreateAmbiguousFailureNotCommitted(t *testing.T) {
	p, _, vm := newTestProvider()
	vm.errCreate = &mockServiceError{status: 500, code: "InternalError", msg: "server error"}

	err := p.Set(context.Background(), "/myapp/prod/API_KEY", "v", provider.SecretMeta{})
	require.Error(t, err)
	var partial *provider.PartialCommitError
	assert.False(t, errors.As(err, &partial))
	assert.Contains(t, err.Error(), "server error")
}

func TestOCISetCreateDefinitiveFailure(t *testing.T) {
	p, _, vm := newTestProvider()
	vm.errCreate = &mockServiceError{status: 403, code: "NotAuthorized", msg: "denied"}

	err := p.Set(context.Background(), "/myapp/prod/API_KEY", "v", provider.SecretMeta{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "denied")
	// Definitive failure: no reconciliation readback happened, so the only
	// vault call is the rejected create.
	assert.Empty(t, vm.updated)
}

func TestOCISetMirrorsExpiresAtTag(t *testing.T) {
	p, _, vm := newTestProvider()
	expires := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	err := p.Set(context.Background(), "/myapp/prod/API_KEY", "v", provider.SecretMeta{
		Tags:      map[string]string{TagExpiresAt: "overridden"},
		ExpiresAt: expires,
	})
	require.NoError(t, err)
	require.Len(t, vm.created, 1)
	created := vm.created[0].CreateSecretDetails
	assert.Equal(t, map[string]string{
		TagExpiresAt: expires.UTC().Format(time.RFC3339),
	}, created.FreeformTags)
}

func TestOCIDelete(t *testing.T) {
	p, sm, vm := newTestProvider()
	addSecret(t, p, sm, vm, "myapp-prod_API_KEY", 1, "v")

	err := p.Delete(context.Background(), "/myapp/prod/API_KEY")
	require.NoError(t, err)
	require.Len(t, vm.deleted, 1)
	deleted := vm.deleted[0]
	assert.Equal(t, "ocid1.secret.oc1..myapp-prod_API_KEY", derefString(deleted.SecretId))
	assert.Nil(t, deleted.TimeOfDeletion)
}

func TestOCIDeleteNotFound(t *testing.T) {
	p, _, _ := newTestProvider()
	err := p.Delete(context.Background(), "/myapp/prod/MISSING")
	assert.ErrorIs(t, err, provider.ErrNotFound)
}

func TestOCIDeleteError(t *testing.T) {
	p, sm, vm := newTestProvider()
	addSecret(t, p, sm, vm, "myapp-prod_API_KEY", 1, "v")
	vm.errDelete = errors.New("delete failed")

	err := p.Delete(context.Background(), "/myapp/prod/API_KEY")
	require.Error(t, err)
}

func TestOCIGetHistoryAscendingWithValues(t *testing.T) {
	p, sm, vm := newTestProvider()
	addSecret(t, p, sm, vm, "myapp-prod_API_KEY", 1, "v1")
	addSecret(t, p, sm, vm, "myapp-prod_API_KEY", 2, "v2")
	addSecret(t, p, sm, vm, "myapp-prod_API_KEY", 3, "v3")

	history, err := p.GetHistory(context.Background(), "/myapp/prod/API_KEY")
	require.NoError(t, err)
	require.Len(t, history, 3)
	for i, want := range []string{"v1", "v2", "v3"} {
		assert.Equal(t, int64(i+1), history[i].Version)
		assert.Equal(t, want, history[i].Value)
		assert.Equal(t, "/myapp/prod/API_KEY", history[i].Key)
	}
}

func TestOCIGetHistoryNotFound(t *testing.T) {
	p, _, _ := newTestProvider()
	_, err := p.GetHistory(context.Background(), "/myapp/prod/MISSING")
	assert.ErrorIs(t, err, provider.ErrNotFound)
}

func TestOCIGetHistoryVersionsError(t *testing.T) {
	p, sm, vm := newTestProvider()
	addSecret(t, p, sm, vm, "myapp-prod_API_KEY", 1, "v1")
	vm.errVersions = errors.New("versions failed")

	_, err := p.GetHistory(context.Background(), "/myapp/prod/API_KEY")
	require.Error(t, err)
}

func TestOCIRollbackSuccess(t *testing.T) {
	p, sm, vm := newTestProvider()
	addSecret(t, p, sm, vm, "myapp-prod_API_KEY", 1, "v1")
	addSecret(t, p, sm, vm, "myapp-prod_API_KEY", 2, "v2")

	err := p.Rollback(context.Background(), "/myapp/prod/API_KEY", 1)
	require.NoError(t, err)
	require.Len(t, vm.updated, 1)
	assert.Equal(t, "ocid1.secret.oc1..myapp-prod_API_KEY", derefString(vm.updated[0].SecretId))
	raw, decErr := base64.StdEncoding.DecodeString(derefString(vm.updated[0].UpdateSecretDetails.SecretContent.(*vault.Base64SecretContentDetails).Content))
	require.NoError(t, decErr)
	assert.Equal(t, "v1", string(raw))
}

func TestOCIRollbackVersionNotFound(t *testing.T) {
	p, sm, vm := newTestProvider()
	addSecret(t, p, sm, vm, "myapp-prod_API_KEY", 1, "v1")

	err := p.Rollback(context.Background(), "/myapp/prod/API_KEY", 99)
	assert.ErrorIs(t, err, provider.ErrNotFound)
}

func TestOCIRollbackGetVersionError(t *testing.T) {
	p, sm, vm := newTestProvider()
	addSecret(t, p, sm, vm, "myapp-prod_API_KEY", 1, "v1")
	sm.errGet = errors.New("boom")
	err := p.Rollback(context.Background(), "/myapp/prod/API_KEY", 1)
	require.Error(t, err)
}

func TestMapErrorClassification(t *testing.T) {
	tests := []struct {
		name         string
		err          error
		wantNotFound bool
	}{
		{"http 404", &mockServiceError{status: 404, code: "NotAuthorizedOrNotFound", msg: "not found"}, true},
		{"oci code", &mockServiceError{status: 401, code: "NotAuthorizedOrNotFound", msg: "not found"}, true},
		{"auth", &mockServiceError{status: 401, code: "NotAuthenticated", msg: "no token"}, false},
		{"plain", errors.New("socket closed"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := mapError("get", "KEY", tt.err)
			if tt.wantNotFound {
				assert.ErrorIs(t, err, provider.ErrNotFound)
			} else {
				assert.NotErrorIs(t, err, provider.ErrNotFound)
				assert.Contains(t, err.Error(), `oci: get "KEY"`)
			}
		})
	}
}

func TestMutationMayHaveCommitted(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"400", &mockServiceError{status: 400}, false},
		{"401", &mockServiceError{status: 401}, false},
		{"403", &mockServiceError{status: 403}, false},
		{"404", &mockServiceError{status: 404}, false},
		{"409", &mockServiceError{status: 409}, true},
		{"429", &mockServiceError{status: 429}, true},
		{"500", &mockServiceError{status: 500}, true},
		{"transport", errors.New("connection reset"), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, mutationMayHaveCommitted(tt.err))
		})
	}
}

func TestFreeformTagsFromMeta(t *testing.T) {
	assert.Nil(t, freeformTagsFromMeta(provider.SecretMeta{}))
	expires := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	tags := freeformTagsFromMeta(provider.SecretMeta{
		Tags:      map[string]string{"team": "core", TagExpiresAt: "old"},
		ExpiresAt: expires,
	})
	assert.Equal(t, map[string]string{
		"team":       "core",
		TagExpiresAt: expires.UTC().Format(time.RFC3339),
	}, tags)
}

func TestHashLinesOrderIndependent(t *testing.T) {
	a := hashLines([]string{"x@1", "y@2"})
	b := hashLines([]string{"y@2", "x@1"})
	assert.Equal(t, a, b)
}

func TestOCIListPagination(t *testing.T) {
	p, sm, vm := newTestProvider()
	addSecret(t, p, sm, vm, "myapp-prod_A", 1, "va")
	addSecret(t, p, sm, vm, "myapp-prod_B", 1, "vb")
	vm.pages = [][]vault.SecretSummary{vm.summaries[:1], vm.summaries[1:]}

	names, err := p.ListNames(context.Background(), "")
	require.NoError(t, err)
	assert.Len(t, names, 2)
	assert.Equal(t, 2, vm.listCalls, "both pages fetched")
}

func TestOCIListBundleFetchError(t *testing.T) {
	p, sm, vm := newTestProvider()
	addSecret(t, p, sm, vm, "myapp-prod_A", 1, "va")
	delete(sm.byName, "myapp-prod_A")

	_, err := p.List(context.Background(), "")
	require.Error(t, err)
	assert.ErrorIs(t, err, provider.ErrNotFound)
}

func TestOCIFingerprintMissingBundle(t *testing.T) {
	p, sm, vm := newTestProvider()
	addSecret(t, p, sm, vm, "myapp-prod_A", 1, "va")
	delete(sm.byName, "myapp-prod_A")

	_, err := p.Fingerprint(context.Background(), "")
	require.Error(t, err)
}

func TestOCIFingerprintNoVersions(t *testing.T) {
	p, sm, vm := newTestProvider()
	addSecret(t, p, sm, vm, "myapp-prod_A", 1, "va")
	// Summary and bundle exist, but the versions listing is empty.
	vm.versionsByOCID["ocid1.secret.oc1..myapp-prod_A"] = nil

	_, err := p.Fingerprint(context.Background(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "has no versions")
}

func TestOCIFingerprintVersionsError(t *testing.T) {
	p, sm, vm := newTestProvider()
	addSecret(t, p, sm, vm, "myapp-prod_A", 1, "va")
	vm.errVersions = errors.New("versions failed")

	_, err := p.Fingerprint(context.Background(), "")
	require.Error(t, err)
}

func TestOCIDeleteListError(t *testing.T) {
	p, _, vm := newTestProvider()
	vm.errList = errors.New("list failed")
	err := p.Delete(context.Background(), "/myapp/prod/API_KEY")
	require.Error(t, err)
}

func TestOCIGetHistoryPerVersionBundleError(t *testing.T) {
	p, sm, vm := newTestProvider()
	addSecret(t, p, sm, vm, "myapp-prod_API_KEY", 1, "v1")
	addSecret(t, p, sm, vm, "myapp-prod_API_KEY", 2, "v2")
	delete(sm.byVersion["myapp-prod_API_KEY"], 2)

	_, err := p.GetHistory(context.Background(), "/myapp/prod/API_KEY")
	require.Error(t, err)
}

func TestDerefHelpersNil(t *testing.T) {
	assert.Equal(t, "", derefString(nil))
	assert.Equal(t, int64(0), derefInt64(nil))
}

func TestDecodeBundleInvalidBase64(t *testing.T) {
	_, err := decodeBundle(secrets.SecretBundle{
		SecretBundleContent: secrets.Base64SecretBundleContentDetails{Content: common.String("!!!not-base64!!!")},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode secret content")
}

func TestNewWithClientsNilClientGuards(t *testing.T) {
	var p *Provider
	_, err := p.Get(context.Background(), "K")
	assert.ErrorIs(t, err, provider.ErrNotFound)
	_, err = p.GetVersion(context.Background(), "K", 1)
	assert.ErrorIs(t, err, provider.ErrNotFound)
}

func TestNewValidationAndConstruction(t *testing.T) {
	isolateOCIAuth(t)

	_, err := New(nil)
	require.Error(t, err)

	_, err = New(&config.ResolvedConfig{Provider: "oci"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "compartment_id is required")

	_, err = New(&config.ResolvedConfig{Provider: "oci", CompartmentID: "c"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "vault_id is required")

	// No auth source in the test environment -> actionable error.
	_, err = New(&config.ResolvedConfig{Provider: "oci", CompartmentID: "c", VaultID: "v"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no authentication available")

	// Auth from OCI_CLI_* env overrides with a generated key: clients
	// construct offline (no network calls at construction time).
	keyPath := writeTestKeyFile(t)
	t.Setenv(EnvUser, "ocid1.user.oc1..env")
	t.Setenv(EnvTenancy, "ocid1.tenancy.oc1..env")
	t.Setenv(EnvFingerprint, "11:22:33:44")
	t.Setenv(EnvKeyFile, keyPath)
	t.Setenv(EnvRegion, "ap-singapore-1")

	p, err := New(&config.ResolvedConfig{
		Provider:      "oci",
		CompartmentID: "ocid1.compartment.oc1..c",
		VaultID:       "ocid1.vault.oc1..v",
		KeyID:         "ocid1.key.oc1..k",
		Path:          "/myapp/prod",
	})
	require.NoError(t, err)
	assert.Equal(t, "oci", p.Name())
	assert.NoError(t, p.Close())
}

func TestNewRegionFromConfigOverride(t *testing.T) {
	isolateOCIAuth(t)
	keyPath := writeTestKeyFile(t)
	t.Setenv(EnvUser, "ocid1.user.oc1..env")
	t.Setenv(EnvTenancy, "ocid1.tenancy.oc1..env")
	t.Setenv(EnvFingerprint, "11:22:33:44")
	t.Setenv(EnvKeyFile, keyPath)
	t.Setenv(EnvRegion, "")

	// cfg.Region overrides the absent env region.
	p, err := New(&config.ResolvedConfig{
		Provider:      "oci",
		CompartmentID: "c",
		VaultID:       "v",
		Region:        "us-ashburn-1",
	})
	require.NoError(t, err)
	assert.Equal(t, "oci", p.Name())

	// No region anywhere -> actionable error.
	_, err = New(&config.ResolvedConfig{Provider: "oci", CompartmentID: "c", VaultID: "v"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no region")
}
