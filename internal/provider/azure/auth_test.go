package azure_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	skazure "github.com/n24q02m/skret/internal/provider/azure"
)

func TestResolveVaultURL_NameOnly(t *testing.T) {
	u, err := skazure.ResolveVaultURL("", "MyVault")
	require.NoError(t, err)
	assert.Equal(t, "https://myvault.vault.azure.net", u)
}

func TestResolveVaultURL_URLOnly(t *testing.T) {
	u, err := skazure.ResolveVaultURL("https://other.vault.azure.net/", "")
	require.NoError(t, err)
	assert.Equal(t, "https://other.vault.azure.net", u, "trailing slash trimmed")
}

func TestResolveVaultURL_BothAgree(t *testing.T) {
	u, err := skazure.ResolveVaultURL("https://myvault.vault.azure.net", "myvault")
	require.NoError(t, err)
	assert.Equal(t, "https://myvault.vault.azure.net", u)
}

func TestResolveVaultURL_Disagree(t *testing.T) {
	_, err := skazure.ResolveVaultURL("https://other.vault.azure.net", "myvault")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "disagree")
}

func TestResolveVaultURL_BadName(t *testing.T) {
	for _, name := range []string{"ab", "has_underscore", "-startswithdash", "way-too-long-name-over-24-chars!"} {
		_, err := skazure.ResolveVaultURL("", name)
		require.Error(t, err, "vault_name %q must be rejected", name)
		assert.Contains(t, err.Error(), "vault_name")
	}
}

func TestResolveVaultURL_BadURL(t *testing.T) {
	for _, raw := range []string{"http://vault.azure.net", "vault.azure.net", "https://"} {
		_, err := skazure.ResolveVaultURL(raw, "")
		require.Error(t, err, "vault_url %q must be rejected", raw)
		assert.Contains(t, err.Error(), "https:// URL")
	}
}

func TestResolveVaultURL_Neither(t *testing.T) {
	_, err := skazure.ResolveVaultURL("", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "one of vault_url or vault_name is required")
}
