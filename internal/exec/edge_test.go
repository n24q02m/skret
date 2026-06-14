package exec_test

import (
	"testing"

	skexec "github.com/n24q02m/skret/internal/exec"
	"github.com/n24q02m/skret/internal/provider"
	"github.com/stretchr/testify/assert"
)

// Values that look like mutual references are kept literal (no expansion).
func TestBuildEnv_RefLikeValuesKeptLiteral(t *testing.T) {
	secrets := []*provider.Secret{
		{Key: "A", Value: "${B}"},
		{Key: "B", Value: "${A}"},
		{Key: "C", Value: "${D}"},
		{Key: "D", Value: "${C}"},
	}
	env := skexec.BuildEnv(secrets, nil, "", nil)

	assert.Len(t, env, 4)
	assert.Contains(t, env, "A=${B}")
	assert.Contains(t, env, "B=${A}")
	assert.Contains(t, env, "C=${D}")
	assert.Contains(t, env, "D=${C}")
}

func TestBuildEnv_UndefinedRefKeptLiteral(t *testing.T) {
	secrets := []*provider.Secret{
		{Key: "A", Value: "${UNDEFINED_VAR}"},
	}
	env := skexec.BuildEnv(secrets, nil, "", nil)
	assert.Contains(t, env, "A=${UNDEFINED_VAR}")
}

func TestBuildEnv_DoubleDollarKeptLiteral(t *testing.T) {
	secrets := []*provider.Secret{
		{Key: "A", Value: "$$VAL"},
	}
	env := skexec.BuildEnv(secrets, nil, "", nil)
	// No expansion: "$$VAL" is injected byte-exact.
	assert.Contains(t, env, "A=$$VAL")
}

func TestBuildEnv_CaseInsensitiveExclude(t *testing.T) {
	secrets := []*provider.Secret{
		{Key: "secret_key", Value: "val"},
	}
	// Case-insensitive exclusion should work
	env := skexec.BuildEnv(secrets, nil, "", []string{"SECRET_KEY"})
	assert.NotContains(t, env, "SECRET_KEY=val")
}

func TestBuildEnv_DuplicateExisting(t *testing.T) {
	existing := []string{"A=1", "A=2"}
	env := skexec.BuildEnv(nil, existing, "", nil)
	// BuildEnv preserves the order and exact strings of 'existing'
	// while using a map for lookup during secret merging.
	assert.Contains(t, env, "A=1")
	assert.Contains(t, env, "A=2")

	// Ensure that secrets don't override even if there are duplicates
	secrets := []*provider.Secret{{Key: "A", Value: "secret"}}
	envWithSecrets := skexec.BuildEnv(secrets, existing, "", nil)
	assert.NotContains(t, envWithSecrets, "A=secret")
}

func TestKeyToEnvName_EdgeCases(t *testing.T) {
	// Exact prefix match - current behavior is ""
	assert.Equal(t, "", skexec.KeyToEnvName("/my/path", "/my/path"))

	// Trailing slash prefix
	assert.Equal(t, "KEY", skexec.KeyToEnvName("/my/path/KEY", "/my/path/"))

	// Empty result after stripping - current behavior is ""
	assert.Equal(t, "", skexec.KeyToEnvName("/my/path/", "/my/path"))

	// Empty prefix
	assert.Equal(t, "A_B", skexec.KeyToEnvName("a/b", ""))
}
