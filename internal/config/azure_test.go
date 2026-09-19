package config_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/n24q02m/skret/internal/config"
)

func azureConfig(vaultURL, vaultName string) *config.Config {
	return &config.Config{
		Version: "1",
		Environments: map[string]config.Environment{
			"prod": {Provider: "azure", VaultURL: vaultURL, VaultName: vaultName},
		},
	}
}

func TestResolve_AzureRequiresVaultRef(t *testing.T) {
	// Per-provider requirement checks run in Resolve (scoped to the selected
	// env), not in structural Validate — the C1 audit fix.
	_, err := config.Resolve(azureConfig("", ""), config.ResolveOpts{})
	require.Error(t, err)
	assert.ErrorContains(t, err, "one of vault_url or vault_name is required for azure provider")
}

func TestResolve_AcceptsAzureVaultName(t *testing.T) {
	_, err := config.Resolve(azureConfig("", "myvault"), config.ResolveOpts{})
	require.NoError(t, err)
	_, err = config.Resolve(azureConfig("https://myvault.vault.azure.net", ""), config.ResolveOpts{})
	require.NoError(t, err)
}

func TestResolve_AzureVaultFieldsFlowThrough(t *testing.T) {
	cfg := azureConfig("", "myvault")
	resolved, err := config.Resolve(cfg, config.ResolveOpts{})
	require.NoError(t, err)
	assert.Equal(t, "azure", resolved.Provider)
	assert.Equal(t, "myvault", resolved.VaultName)
	assert.Empty(t, resolved.VaultURL)
}

func TestResolve_AzureVaultURLFlowThrough(t *testing.T) {
	cfg := azureConfig("https://myvault.vault.azure.net", "")
	resolved, err := config.Resolve(cfg, config.ResolveOpts{})
	require.NoError(t, err)
	assert.Equal(t, "https://myvault.vault.azure.net", resolved.VaultURL)
}
