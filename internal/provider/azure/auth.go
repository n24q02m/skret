package azure

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
)

// defaultVaultSuffix is the public-cloud Key Vault endpoint suffix used to
// derive vault_url from vault_name. Sovereign clouds must set vault_url
// explicitly.
const defaultVaultSuffix = "vault.azure.net"

// vaultNameRE is Azure's vault-name rule: 3-24 characters, alphanumeric
// with dashes, starting and ending with an alphanumeric.
var vaultNameRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9-]{1,22}[a-zA-Z0-9]$`)

// newDefaultClient builds an azsecrets client on the DefaultAzureCredential
// chain: AZURE_TENANT_ID/AZURE_CLIENT_ID/AZURE_CLIENT_SECRET environment
// variables, managed identity, then Azure CLI login. No prompt: every step
// of the chain is non-interactive.
func newDefaultClient(vaultURL string) (SecretsClient, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf(
			"azure: no usable credential (checked AZURE_TENANT_ID/AZURE_CLIENT_ID/AZURE_CLIENT_SECRET, managed identity, Azure CLI): %w", err,
		)
	}
	client, err := azsecrets.NewClient(vaultURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("azure: create Key Vault client for %s: %w", vaultURL, err)
	}
	return client, nil
}

// ResolveVaultURL resolves the vault endpoint from config. One of
// vaultURL or vaultName is required; vaultName derives
// https://<name>.vault.azure.net; setting both requires them to agree so a
// typo cannot point the name at a different vault than the URL.
func ResolveVaultURL(vaultURL, vaultName string) (string, error) {
	name := strings.ToLower(strings.TrimSpace(vaultName))
	rawURL := strings.TrimSpace(vaultURL)

	if name != "" && !vaultNameRE.MatchString(name) {
		return "", fmt.Errorf("azure: vault_name %q: must be 3-24 alphanumeric or dash characters", vaultName)
	}

	if rawURL != "" {
		u, err := url.Parse(rawURL)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return "", fmt.Errorf("azure: vault_url %q: must be an absolute https:// URL", rawURL)
		}
		if name != "" && !strings.EqualFold(u.Host, name+"."+defaultVaultSuffix) {
			return "", fmt.Errorf(
				"azure: vault_url %q and vault_name %q disagree (name derives https://%s.%s)",
				rawURL, vaultName, name, defaultVaultSuffix,
			)
		}
		return strings.TrimSuffix(rawURL, "/"), nil
	}
	if name != "" {
		return fmt.Sprintf("https://%s.%s", name, defaultVaultSuffix), nil
	}
	return "", errors.New("azure: one of vault_url or vault_name is required for the azure provider")
}
