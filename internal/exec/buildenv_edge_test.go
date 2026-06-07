package exec_test

import (
	"testing"

	"github.com/n24q02m/skret/internal/exec"
	"github.com/n24q02m/skret/internal/provider"
	"github.com/stretchr/testify/assert"
)

func TestBuildEnv_DuplicateSecrets(t *testing.T) {
	secrets := []*provider.Secret{
		{Key: "DUP", Value: "first"},
		{Key: "DUP", Value: "second"},
	}
	env := exec.BuildEnv(secrets, nil, "", nil)
	assert.Contains(t, env, "DUP=second")
	// Ensure it's not present twice with different values
	assert.NotContains(t, env, "DUP=first")
}

func TestBuildEnv_SecretMatchesPrefix(t *testing.T) {
	// If key matches prefix exactly, name becomes empty
	secrets := []*provider.Secret{
		{Key: "/app/prod", Value: "val"},
	}
	env := exec.BuildEnv(secrets, nil, "/app/prod", nil)
	// Empty name "=val" is generally undesirable but let's see what happens.
	// Looking at KeyToEnvName, if key matches prefix, it returns "".
	// BuildEnv then uses it as a key in secretVars.
	assert.Contains(t, env, "=val")
}

func TestBuildEnv_ExcludeCaseInsensitivity(t *testing.T) {
	secrets := []*provider.Secret{
		{Key: "SECRET_VAR", Value: "val"},
	}
	exclude := []string{"secret_var"}
	env := exec.BuildEnv(secrets, nil, "", exclude)
	for _, e := range env {
		assert.NotContains(t, e, "SECRET_VAR")
	}
}

func TestBuildEnv_ExpansionMissingVar(t *testing.T) {
	secrets := []*provider.Secret{
		{Key: "A", Value: "val-${MISSING}-end"},
	}
	env := exec.BuildEnv(secrets, nil, "", nil)
	assert.Contains(t, env, "A=val--end")
}

func TestBuildEnv_ExpansionEscapedDollar(t *testing.T) {
	secrets := []*provider.Secret{
		{Key: "A", Value: "price-$$100"},
	}
	env := exec.BuildEnv(secrets, nil, "", nil)
	assert.Contains(t, env, "A=price-100")
}

func TestKeyToEnvName_EmptyAndSlashes(t *testing.T) {
	assert.Equal(t, "", exec.KeyToEnvName("", ""))
	assert.Equal(t, "_", exec.KeyToEnvName("/", ""))
	assert.Equal(t, "__", exec.KeyToEnvName("//", ""))
	assert.Equal(t, "", exec.KeyToEnvName("/prefix", "/prefix"))
}

func TestBuildEnv_ExistingMalformed(t *testing.T) {
	existing := []string{"MALFORMED", "KEY=VALUE"}
	env := exec.BuildEnv(nil, existing, "", nil)
	assert.Contains(t, env, "MALFORMED")
	assert.Contains(t, env, "KEY=VALUE")
}

func TestBuildEnv_ExpansionFromHostEnv(t *testing.T) {
	t.Setenv("EXTERNAL_VAR", "ext_val")
	secrets := []*provider.Secret{
		{Key: "A", Value: "${EXTERNAL_VAR}"},
	}
	env := exec.BuildEnv(secrets, nil, "", nil)
	assert.Contains(t, env, "A=ext_val")
}
