package exec_test

import (
	"testing"

	skexec "github.com/n24q02m/skret/internal/exec"
	"github.com/n24q02m/skret/internal/provider"
	"github.com/stretchr/testify/assert"
)

func TestBuildEnv(t *testing.T) {
	secrets := []*provider.Secret{
		{Key: "DB_URL", Value: "postgres://localhost"},
		{Key: "API_KEY", Value: "secret"},
		{Key: "EXCLUDED", Value: "skip"},
	}
	existing := []string{"HOME=/home/user", "PATH=/usr/bin", "DB_URL=old_value"}
	exclude := []string{"EXCLUDED"}

	env := skexec.BuildEnv(secrets, existing, "", exclude)

	assert.Contains(t, env, "HOME=/home/user")
	assert.Contains(t, env, "PATH=/usr/bin")
	assert.Contains(t, env, "DB_URL=old_value")
	assert.Contains(t, env, "API_KEY=secret")
	for _, e := range env {
		assert.NotContains(t, e, "EXCLUDED")
	}
}

func TestBuildEnv_PathStripping(t *testing.T) {
	secrets := []*provider.Secret{
		{Key: "/kp/prod/DB_URL", Value: "pg://host"},
		{Key: "/kp/prod/sub/NESTED", Value: "val"},
	}
	env := skexec.BuildEnv(secrets, nil, "/kp/prod", nil)

	assert.Contains(t, env, "DB_URL=pg://host")
	assert.Contains(t, env, "SUB_NESTED=val")
}
