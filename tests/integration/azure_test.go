package integration_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/n24q02m/skret/internal/config"
	"github.com/n24q02m/skret/internal/provider"
	skazure "github.com/n24q02m/skret/internal/provider/azure"
	"github.com/stretchr/testify/require"
)

func TestAzureIntegration(t *testing.T) {
	if os.Getenv("AZURE_INTEGRATION_TEST") == "" {
		t.Skip("Skipping Azure integration tests; set AZURE_INTEGRATION_TEST=1 and provide AZURE_TENANT_ID/AZURE_CLIENT_ID/AZURE_CLIENT_SECRET or another DefaultAzureCredential source")
	}

	cfg := &config.ResolvedConfig{
		Provider:  "azure",
		VaultName: os.Getenv("AZURE_VAULT_NAME"),
		VaultURL:  os.Getenv("AZURE_VAULT_URL"),
	}

	p, err := skazure.New(cfg)
	require.NoError(t, err)
	defer p.Close() //nolint:errcheck

	ctx := context.Background()

	// Test write
	meta := provider.SecretMeta{Description: "Integration test secret"}
	err = p.Set(ctx, "skret-int-DB-URL", "postgres://localhost:5432/test", meta)
	require.NoError(t, err, "failed to set secret")

	time.Sleep(1 * time.Second) // allow Key Vault write propagation

	// Test read (underscore alias resolves to the same sanitized name)
	s, err := p.Get(ctx, "skret-int-DB-URL")
	require.NoError(t, err, "failed to get secret")
	require.Equal(t, "postgres://localhost:5432/test", s.Value)

	// Test list
	secrets, err := p.List(ctx, "skret-int-")
	require.NoError(t, err, "failed to list secrets")
	require.NotEmpty(t, secrets, "expected at least one secret")

	// Test delete
	err = p.Delete(ctx, "skret-int-DB-URL")
	require.NoError(t, err, "failed to delete secret")
}
