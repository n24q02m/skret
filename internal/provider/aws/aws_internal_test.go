package aws

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/n24q02m/skret/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	origLoadConfig := loadConfig
	defer func() { loadConfig = origLoadConfig }()

	t.Run("Success", func(t *testing.T) {
		loadConfig = func(ctx context.Context, region, profile string) (aws.Config, error) {
			return aws.Config{Region: "us-east-1"}, nil
		}

		cfg := &config.ResolvedConfig{
			Region: "us-east-1",
			Path:   "/test/path",
		}

		p, err := New(cfg)
		require.NoError(t, err)
		require.NotNil(t, p)

		awsP, ok := p.(*Provider)
		require.True(t, ok)
		assert.Equal(t, "/test/path", awsP.path)
		assert.NotNil(t, awsP.client)
	})

	t.Run("Error", func(t *testing.T) {
		loadConfig = func(ctx context.Context, region, profile string) (aws.Config, error) {
			return aws.Config{}, errors.New("load error")
		}

		cfg := &config.ResolvedConfig{}
		p, err := New(cfg)
		assert.Error(t, err)
		assert.Nil(t, p)
		assert.Contains(t, err.Error(), "load error")
	})
}

func TestLoadAWSConfig(t *testing.T) {
	// Simple sanity check for loadAWSConfig which actually calls AWS SDK
	// This will likely use default credentials or fail gracefully if none found
	// We just want to see it executed for coverage if possible, or at least not crash
	ctx := context.Background()
	_, _ = loadAWSConfig(ctx, "", "")
	_, _ = loadAWSConfig(ctx, "us-east-1", "default")
}
