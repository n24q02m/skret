package differ

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/n24q02m/skret/internal/provider"
)

// stubProvider implements just enough of provider.SecretProvider for List.
type stubProvider struct {
	provider.SecretProvider
	secrets []*provider.Secret
	listErr error
}

func (s stubProvider) List(_ context.Context, _ string) ([]*provider.Secret, error) {
	return s.secrets, s.listErr
}

func TestEnvSource_NormalizesKeys(t *testing.T) {
	p := stubProvider{secrets: []*provider.Secret{
		{Key: "/myapp/prod/DB_URL", Value: "x"},
		{Key: "/myapp/prod/api-key", Value: "y"},
	}}
	src := NewEnvSource("env:prod", p, "/myapp/prod")

	snap, err := src.Read(context.Background())
	require.NoError(t, err)
	assert.True(t, snap.CanReadValues)
	assert.Equal(t, "x", snap.Secrets["DB_URL"])
	assert.Equal(t, "y", snap.Secrets["API_KEY"]) // hyphen+lowercase normalized
	assert.Equal(t, "env:prod", src.Label())
}

func TestEnvSource_ListError(t *testing.T) {
	src := NewEnvSource("env:prod", stubProvider{listErr: assert.AnError}, "/myapp/prod")
	_, err := src.Read(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "env:prod")
}
