package integration_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/n24q02m/skret/internal/config"
	skaws "github.com/n24q02m/skret/internal/provider/aws"
	"github.com/n24q02m/skret/internal/provider"
	"github.com/stretchr/testify/require"
)

func TestAWSIntegration(t *testing.T) {
	if os.Getenv("AWS_INTEGRATION_TEST") == "" {
		t.Skip("Skipping AWS integration tests; set AWS_INTEGRATION_TEST=1 and use LocalStack or real AWS credentials")
	}

	cfg := &config.ResolvedConfig{
		Provider: "aws",
		Path:     "/skret/test",
		Region:   os.Getenv("AWS_REGION"),
		Profile:  os.Getenv("AWS_PROFILE"),
	}

	p, err := skaws.New(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	// Test write
	meta := provider.SecretMeta{Description: "Integration test secret"}
	err = p.Set(ctx, "/skret/test/DB_URL", "postgres://localhost:5432/test", meta)
	require.NoError(t, err, "failed to set secret")

	time.Sleep(1 * time.Second) // allow eventual consistency on SSM

	// Test read
	s, err := p.Get(ctx, "/skret/test/DB_URL")
	require.NoError(t, err, "failed to get secret")
	require.Equal(t, "postgres://localhost:5432/test", s.Value)

	// Test list
	list, err := p.List(ctx, "/skret/test")
	require.NoError(t, err, "failed to list secrets")
	require.NotEmpty(t, list)

	// Test delete
	err = p.Delete(ctx, "/skret/test/DB_URL")
	require.NoError(t, err, "failed to delete secret")
}
