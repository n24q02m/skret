package integration_test

import (
	"context"
	"os"
	"testing"

	"github.com/n24q02m/skret/internal/config"
	"github.com/n24q02m/skret/internal/provider"
	skgcp "github.com/n24q02m/skret/internal/provider/gcp"
	"github.com/stretchr/testify/require"
)

// TestGCPIntegration runs against a real GCP project. It is owner-gated:
// opt in with SKRET_E2E_GCP=1 plus ADC (GOOGLE_APPLICATION_CREDENTIALS,
// `gcloud auth application-default login`, or workload identity) and
// GCP_TEST_PROJECT.
func TestGCPIntegration(t *testing.T) {
	if os.Getenv("SKRET_E2E_GCP") == "" {
		t.Skip("Skipping GCP integration tests; set SKRET_E2E_GCP=1 with ADC and GCP_TEST_PROJECT")
	}
	project := os.Getenv("GCP_TEST_PROJECT")
	if project == "" {
		t.Fatal("GCP_TEST_PROJECT is required when SKRET_E2E_GCP is set")
	}

	cfg := &config.ResolvedConfig{
		Provider: "gcp",
		Project:  project,
		Region:   os.Getenv("GCP_TEST_LOCATION"), // optional regional location
	}

	p, err := skgcp.New(cfg)
	require.NoError(t, err)
	defer func() { _ = p.Close() }()

	ctx := context.Background()
	const key = "SKRET_E2E_KEY"

	// Write (create path on first run, update path afterwards).
	err = p.Set(ctx, key, "integration-value", provider.SecretMeta{Description: "skret e2e"})
	require.NoError(t, err, "failed to set secret")

	// Read back.
	s, err := p.Get(ctx, key)
	require.NoError(t, err, "failed to get secret")
	require.Equal(t, "integration-value", s.Value)

	// List.
	list, err := p.List(ctx, "")
	require.NoError(t, err, "failed to list secrets")
	require.NotEmpty(t, list)

	// History + rollback.
	history, err := p.GetHistory(ctx, key)
	require.NoError(t, err)
	if len(history) >= 2 {
		require.NoError(t, p.Rollback(ctx, key, history[0].Version))
	}

	// Delete.
	err = p.Delete(ctx, key)
	require.NoError(t, err, "failed to delete secret")
}
