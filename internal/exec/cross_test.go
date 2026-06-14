package exec_test

import (
	"os"
	"testing"

	skexec "github.com/n24q02m/skret/internal/exec"
	"github.com/n24q02m/skret/internal/provider"
	"github.com/stretchr/testify/assert"
)

// TestBuildEnv_NoExpansion asserts that '${REF}' tokens in secret values are
// NOT expanded — they are injected literally. Cross-secret reference is served
// by the explicit `skret template` command, not by silent expansion in run.
func TestBuildEnv_NoExpansion(t *testing.T) {
	secrets := []*provider.Secret{
		{Key: "DB_USER", Value: "admin"},
		{Key: "DB_PASS", Value: "supersecret"},
		{Key: "DB_URL", Value: "postgres://${DB_USER}:${DB_PASS}@localhost"},
		{Key: "DB_CONNECTION", Value: "connected to ${DB_URL}"},
	}

	os.Setenv("TEST_REGION", "us-east-1")
	defer os.Unsetenv("TEST_REGION")

	secretsWithOsEnv := append(secrets, &provider.Secret{Key: "TEST_INFO", Value: "region=${TEST_REGION}"})
	secretsWithOsEnv = append(secretsWithOsEnv, &provider.Secret{Key: "EXISTING_OVERRIDE", Value: "port=${PORT}"})

	existing := []string{"PORT=8080"}

	env := skexec.BuildEnv(secretsWithOsEnv, existing, "", nil)

	assert.Contains(t, env, "DB_USER=admin")
	assert.Contains(t, env, "DB_URL=postgres://${DB_USER}:${DB_PASS}@localhost")
	assert.Contains(t, env, "DB_CONNECTION=connected to ${DB_URL}")
	assert.Contains(t, env, "TEST_INFO=region=${TEST_REGION}")
	assert.Contains(t, env, "EXISTING_OVERRIDE=port=${PORT}")
	// existing PORT is preserved as-is (existing wins, untouched).
	assert.Contains(t, env, "PORT=8080")
}
