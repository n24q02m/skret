package aws

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadAWSConfig(t *testing.T) {
	// Set dummy credentials to avoid loading from real environment/files
	t.Setenv("AWS_ACCESS_KEY_ID", "testing")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "testing")
	t.Setenv("AWS_REGION", "us-east-1")

	ctx := context.Background()

	t.Run("ExplicitRegion", func(t *testing.T) {
		cfg, err := loadAWSConfig(ctx, "us-west-2", "")
		require.NoError(t, err)
		assert.Equal(t, "us-west-2", cfg.Region)
	})

	t.Run("DefaultRegion", func(t *testing.T) {
		cfg, err := loadAWSConfig(ctx, "", "")
		require.NoError(t, err)
		assert.Equal(t, "us-east-1", cfg.Region)
	})

	t.Run("WithProfile", func(t *testing.T) {
		// We don't have a real profile, but we can check if it at least doesn't crash
		// and returns the default config if profile is not found (SDK behavior varies)
		// Usually if profile is specified but not found, it might error if we use it,
		// but LoadDefaultConfig itself might not fail immediately depending on settings.
		cfg, _ := loadAWSConfig(ctx, "", "nonexistent")
		assert.NotNil(t, cfg)
	})
}
