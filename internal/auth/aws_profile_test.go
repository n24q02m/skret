package auth_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/n24q02m/skret/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAWSProfileFlow_List(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".aws"), 0o700))
	cfg := `[default]
region = us-east-1

[profile dev]
region = ap-southeast-1

[profile prod]
region = us-west-2
role_arn = arn:aws:iam::111:role/ops
source_profile = default
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".aws", "config"), []byte(cfg), 0o600))
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)

	flow := auth.NewAWSProfileFlow()
	profiles, err := flow.List()
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"default", "dev", "prod"}, profiles)

	cred, err := flow.Login(context.Background(), map[string]string{"profile": "dev"})
	require.NoError(t, err)
	assert.Equal(t, "profile", cred.Method)
	assert.Equal(t, "dev", cred.Metadata["profile"])
	assert.Equal(t, "ap-southeast-1", cred.Metadata["region"])
}

func TestAWSProfileFlow_MissingConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	flow := auth.NewAWSProfileFlow()
	_, err := flow.List()
	require.Error(t, err)
}

func TestAWSProfileFlow_UnknownProfile(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".aws"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".aws", "config"), []byte("[default]\nregion = us-east-1\n"), 0o600))
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)

	flow := auth.NewAWSProfileFlow()
	_, err := flow.Login(context.Background(), map[string]string{"profile": "missing"})
	require.Error(t, err)
}
