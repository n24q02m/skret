package oci

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/secrets"
	"github.com/oracle/oci-go-sdk/v65/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/n24q02m/skret/internal/config"
	"github.com/n24q02m/skret/internal/provider"
)

// pagedVersionsClient serves ListSecretVersions one page per call, the way
// OCI paginates large version listings.
type pagedVersionsClient struct {
	*mockVaultsClient
	pages [][]int64
	calls int
}

func (c *pagedVersionsClient) ListSecretVersions(_ context.Context, _ vault.ListSecretVersionsRequest) (vault.ListSecretVersionsResponse, error) {
	page := c.pages[c.calls]
	c.calls++
	items := make([]vault.SecretVersionSummary, 0, len(page))
	for _, v := range page {
		items = append(items, vault.SecretVersionSummary{VersionNumber: common.Int64(v)})
	}
	resp := vault.ListSecretVersionsResponse{Items: items}
	if c.calls < len(c.pages) {
		resp.OpcNextPage = common.String("next-page")
	}
	return resp, nil
}

// writeEncryptedTestKeyFile writes a freshly generated RSA key as a
// passphrase-encrypted legacy PEM, the encrypted format the OCI SDK decrypts
// with the configured pass phrase.
func writeEncryptedTestKeyFile(t *testing.T, passphrase string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	//nolint:staticcheck // SA1019: legacy PEM encryption is exactly what OCI's API-key loader accepts with a pass phrase.
	block, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key), []byte(passphrase), x509.PEMCipherAES256)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "encrypted_key.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(block), 0o600))
	return path
}

func setEnvAPIKey(t *testing.T, keyPath string) {
	t.Helper()
	t.Setenv(EnvUser, "ocid1.user.oc1..env")
	t.Setenv(EnvTenancy, "ocid1.tenancy.oc1..env")
	t.Setenv(EnvFingerprint, "11:22:33:44")
	t.Setenv(EnvKeyFile, keyPath)
	t.Setenv(EnvRegion, "ap-singapore-1")
}

var testVaultConfig = &config.ResolvedConfig{
	Provider:      "oci",
	CompartmentID: "ocid1.compartment.oc1..c",
	VaultID:       "ocid1.vault.oc1..v",
	Path:          "/myapp/prod",
}

// When both env overrides and a config file exist, the providers compose:
// fields set in the environment win and the file fills the rest (here the
// region, which the environment leaves unset).
func TestResolveConfigurationProviderComposesEnvAndExistingFile(t *testing.T) {
	keyPath := writeTestKeyFile(t)
	home := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".oci"), 0o700))
	require.NoError(t, writeFile(filepath.Join(home, ".oci", "config"), stubOCIConfigFile))
	env := map[string]string{
		EnvUser:        "ocid1.user.oc1..env",
		EnvTenancy:     "ocid1.tenancy.oc1..env",
		EnvFingerprint: "11:22:33:44",
		EnvKeyFile:     keyPath,
	}
	deps := defaultAuthDeps()
	deps.lookupEnv = func(key string) (string, bool) {
		v, ok := env[key]
		return v, ok
	}
	deps.homeDir = func() (string, error) { return home, nil }

	p, err := resolveConfigurationProvider(deps, "")
	require.NoError(t, err)
	tenancy, err := p.TenancyOCID()
	require.NoError(t, err)
	assert.Equal(t, "ocid1.tenancy.oc1..env", tenancy, "env wins over the file")
	region, err := p.Region()
	require.NoError(t, err)
	assert.Equal(t, "us-ashburn-1", region, "file fills fields the env leaves unset")
}

// A home directory that cannot be resolved (error or empty) means the config
// file source is unavailable, not a failure of its own.
func TestResolveConfigurationProviderUnresolvableHome(t *testing.T) {
	for name, homeDir := range map[string]homeDirFunc{
		"error": func() (string, error) { return "", errors.New("no home directory") },
		"empty": func() (string, error) { return "", nil },
	} {
		t.Run(name, func(t *testing.T) {
			deps := defaultAuthDeps()
			deps.lookupEnv = func(string) (string, bool) { return "", false }
			deps.homeDir = homeDir
			_, err := resolveConfigurationProvider(deps, "")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "no authentication available")
			assert.NotContains(t, err.Error(), "no home directory")
		})
	}
}

// OCI_CLI_PASS_PHRASE unlocks an encrypted API key: with it the clients
// build, without it (or with a wrong one) client construction fails.
func TestNewUsesPassPhraseForEncryptedKey(t *testing.T) {
	isolateOCIAuth(t)
	setEnvAPIKey(t, writeEncryptedTestKeyFile(t, "correct-phrase"))

	t.Setenv(EnvPassPhrase, "correct-phrase")
	p, err := New(testVaultConfig)
	require.NoError(t, err)
	assert.Equal(t, "oci", p.Name())

	for _, phrase := range []string{"", "wrong-phrase"} {
		t.Setenv(EnvPassPhrase, phrase)
		p, err := New(testVaultConfig)
		assert.Nil(t, p, "pass phrase %q", phrase)
		require.Error(t, err, "pass phrase %q", phrase)
		assert.Contains(t, err.Error(), "oci: create secrets client: ", "pass phrase %q", phrase)
		assert.NotContains(t, err.Error(), "correct-phrase")
	}
}

// When the OCI developer-tool configuration enables only the Secrets service,
// the vault client cannot be built and New reports which client failed.
func TestNewReportsDisabledVaultService(t *testing.T) {
	isolateOCIAuth(t)
	setEnvAPIKey(t, writeTestKeyFile(t))

	common.OciSdkEnabledServicesMu.RLock()
	hadSecrets := common.OciSdkEnabledServicesMap["secrets"]
	common.OciSdkEnabledServicesMu.RUnlock()
	common.AddServiceToEnabledServicesMap("secrets")
	t.Cleanup(func() {
		if hadSecrets {
			return
		}
		common.OciSdkEnabledServicesMu.Lock()
		defer common.OciSdkEnabledServicesMu.Unlock()
		delete(common.OciSdkEnabledServicesMap, "secrets")
	})
	require.False(t, common.CheckForEnabledServices("vault"), "precondition: vault disabled")

	p, err := New(testVaultConfig)
	assert.Nil(t, p)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "oci: create vault client: ")
}

// Every key-taking method rejects a key that cannot become an OCI secret
// name before calling the service.
func TestInvalidKeysRejectedBeforeServiceCalls(t *testing.T) {
	p, sm, vm := newTestProvider()
	const bad = "/myapp/prod/BAD KEY"

	_, err := p.GetVersion(context.Background(), bad, 1)
	assert.ErrorContains(t, err, "invalid secret name")
	assert.ErrorContains(t, p.Set(context.Background(), bad, "v", provider.SecretMeta{}), "invalid secret name")
	assert.ErrorContains(t, p.Delete(context.Background(), bad), "invalid secret name")
	_, err = p.GetHistory(context.Background(), bad)
	assert.ErrorContains(t, err, "invalid secret name")

	assert.Empty(t, sm.calls)
	assert.Equal(t, 0, vm.listCalls)
	assert.Empty(t, vm.created)
	assert.Empty(t, vm.updated)
	assert.Empty(t, vm.deleted)
}

// List and GetHistory fail on a bundle without base64 content instead of
// returning an empty value.
func TestUndecodableBundlesFailListAndHistory(t *testing.T) {
	p, sm, vm := newTestProvider()
	addSecret(t, p, sm, vm, "myapp-prod_API_KEY", 1, "v1")
	empty := secrets.SecretBundle{SecretId: common.String("ocid1.secret.oc1..myapp-prod_API_KEY"), VersionNumber: common.Int64(1)}

	sm.byName["myapp-prod_API_KEY"] = empty
	_, err := p.List(context.Background(), "")
	assert.ErrorContains(t, err, "has no base64 content")

	sm.byVersion["myapp-prod_API_KEY"][1] = empty
	_, err = p.GetHistory(context.Background(), "/myapp/prod/API_KEY")
	assert.ErrorContains(t, err, "has no base64 content")
}

// Updating an existing secret carries the description and freeform tags into
// the update request.
func TestSetUpdateCarriesDescriptionAndTags(t *testing.T) {
	p, sm, vm := newTestProvider()
	addSecret(t, p, sm, vm, "myapp-prod_API_KEY", 3, "old-value")

	require.NoError(t, p.Set(context.Background(), "/myapp/prod/API_KEY", "new-value", provider.SecretMeta{
		Description: "rotated by test",
		Tags:        map[string]string{"env": "prod"},
	}))
	require.Len(t, vm.updated, 1)
	details := vm.updated[0].UpdateSecretDetails
	assert.Equal(t, "rotated by test", derefString(details.Description))
	assert.Equal(t, map[string]string{"env": "prod"}, details.FreeformTags)
}

// Delete keeps paging the name-filtered listing until it finds the secret.
func TestDeleteFindsSecretOnLaterPage(t *testing.T) {
	p, sm, vm := newTestProvider()
	addSecret(t, p, sm, vm, "myapp-prod_OTHER", 1, "o")
	addSecret(t, p, sm, vm, "myapp-prod_API_KEY", 1, "v")
	vm.pages = [][]vault.SecretSummary{vm.summaries[:1], vm.summaries[1:]}

	require.NoError(t, p.Delete(context.Background(), "/myapp/prod/API_KEY"))
	assert.Equal(t, 2, vm.listCalls, "second page fetched")
	require.Len(t, vm.deleted, 1)
	assert.Equal(t, "ocid1.secret.oc1..myapp-prod_API_KEY", derefString(vm.deleted[0].SecretId))
}

// Fingerprint reads every page of versions and keys each secret by its
// highest version, regardless of listing order.
func TestFingerprintUsesHighestVersionAcrossPages(t *testing.T) {
	p, sm, vm := newTestProvider()
	addSecret(t, p, sm, vm, "myapp-prod_A", 2, "va")
	paged := &pagedVersionsClient{mockVaultsClient: vm, pages: [][]int64{{1}, {3, 2}}}
	p.vaults = paged

	fp, err := p.Fingerprint(context.Background(), "")
	require.NoError(t, err)
	assert.Equal(t, hashLines([]string{"myapp-prod_A@3"}), fp)
	assert.Equal(t, 2, paged.calls, "both version pages fetched")
}

// A bundle name outside the given prefix keeps its raw secret name as the
// key instead of being dropped or mangled.
func TestSecretFromBundleKeepsForeignNameAsKey(t *testing.T) {
	s, err := secretFromBundle("/other/path", "myapp-prod_A", ociBundle("ocid1.secret.oc1..a", 4, "va"))
	require.NoError(t, err)
	assert.Equal(t, "myapp-prod_A", s.Key)
	assert.Equal(t, int64(4), s.Version)
	assert.Equal(t, "va", s.Value)
}

// mapError passes a nil error through as nil.
func TestMapErrorNil(t *testing.T) {
	assert.NoError(t, mapError("get", "KEY", nil))
}
