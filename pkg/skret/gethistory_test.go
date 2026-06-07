package skret

import (
	"context"
	"testing"
	"time"

	"github.com/n24q02m/skret/internal/config"
	"github.com/n24q02m/skret/internal/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_GetHistory_EdgeCases(t *testing.T) {
	ctx := context.Background()
	mock := &mockProvider{name: "mock"}
	client := &Client{
		provider: mock,
		config:   &config.ResolvedConfig{Path: "/test/"},
	}

	t.Run("EmptyHistory", func(t *testing.T) {
		mock.getHistoryFunc = func(ctx context.Context, key string) ([]*provider.Secret, error) {
			return []*provider.Secret{}, nil
		}
		history, err := client.GetHistory(ctx, "k1")
		require.NoError(t, err)
		assert.Empty(t, history)
	})

	t.Run("NilHistory", func(t *testing.T) {
		mock.getHistoryFunc = func(ctx context.Context, key string) ([]*provider.Secret, error) {
			return nil, nil
		}
		history, err := client.GetHistory(ctx, "k1")
		require.NoError(t, err)
		assert.Nil(t, history)
	})

	t.Run("MultipleVersions", func(t *testing.T) {
		expected := []*provider.Secret{
			{Key: "k1", Value: "v2", Version: 2},
			{Key: "k1", Value: "v1", Version: 1},
		}
		mock.getHistoryFunc = func(ctx context.Context, key string) ([]*provider.Secret, error) {
			return expected, nil
		}
		history, err := client.GetHistory(ctx, "k1")
		require.NoError(t, err)
		assert.Equal(t, expected, history)
	})

	t.Run("HistoryWithMetadata", func(t *testing.T) {
		now := time.Now().Truncate(time.Second)
		expected := []*provider.Secret{
			{
				Key:     "k1",
				Value:   "v1",
				Version: 1,
				Meta: provider.SecretMeta{
					Description: "initial version",
					CreatedAt:   now,
					CreatedBy:   "user1",
				},
			},
		}
		mock.getHistoryFunc = func(ctx context.Context, key string) ([]*provider.Secret, error) {
			return expected, nil
		}
		history, err := client.GetHistory(ctx, "k1")
		require.NoError(t, err)
		require.Len(t, history, 1)
		assert.Equal(t, expected[0].Meta.Description, history[0].Meta.Description)
		assert.Equal(t, expected[0].Meta.CreatedAt, history[0].Meta.CreatedAt)
		assert.Equal(t, expected[0].Meta.CreatedBy, history[0].Meta.CreatedBy)
	})
}
