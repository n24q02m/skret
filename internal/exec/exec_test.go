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

func TestBuildEnv_EmptySecrets(t *testing.T) {
	env := skexec.BuildEnv(nil, []string{"HOME=/root"}, "", nil)
	assert.Equal(t, []string{"HOME=/root"}, env)
}

func TestKeyToEnvName_NoPrefix(t *testing.T) {
	assert.Equal(t, "DB_URL", skexec.KeyToEnvName("DB_URL", ""))
	assert.Equal(t, "API_KEY", skexec.KeyToEnvName("api_key", ""))
}

func TestKeyToEnvName_WithPrefix(t *testing.T) {
	assert.Equal(t, "DB_URL", skexec.KeyToEnvName("/app/prod/DB_URL", "/app/prod"))
	assert.Equal(t, "DB_URL", skexec.KeyToEnvName("/app/prod/DB_URL", "/app/prod/"))
}

func TestKeyToEnvName_SlashToUnderscore(t *testing.T) {
	assert.Equal(t, "A_B_C", skexec.KeyToEnvName("/prefix/a/b/c", "/prefix"))
}

func TestKeyToEnvName_NoMatch(t *testing.T) {
	// Key doesn't start with prefix — whole key used
	result := skexec.KeyToEnvName("/other/path/KEY", "/my/prefix")
	assert.Equal(t, "_OTHER_PATH_KEY", result)
}

func TestKeyToEnvName_NonAscii(t *testing.T) {
	assert.Equal(t, "UNICODE_秘_密", skexec.KeyToEnvName("unicode/秘/密", ""))
}

func TestBuildEnv_ExpansionSecretVars(t *testing.T) {
	secrets := []*provider.Secret{
		{Key: "A", Value: "1"},
		{Key: "B", Value: "${A}"},
	}
	existing := []string{}

	env := skexec.BuildEnv(secrets, existing, "", nil)

	assert.Contains(t, env, "B=1")
}

func TestBuildEnv_ExpansionExistingVars(t *testing.T) {
	secrets := []*provider.Secret{
		{Key: "B", Value: "${A}"},
	}
	existing := []string{"A=2"}

	env := skexec.BuildEnv(secrets, existing, "", nil)

	assert.Contains(t, env, "B=2")
}

func TestBuildEnv_ExpansionHostEnv(t *testing.T) {
	t.Setenv("HOST_ENV", "host_value")
	secrets := []*provider.Secret{
		{Key: "DB_PASS", Value: "${HOST_ENV}"},
	}
	existing := []string{}

	env := skexec.BuildEnv(secrets, existing, "", nil)

	assert.Contains(t, env, "DB_PASS=host_value")
}

func TestBuildEnv_ExistingNoValue(t *testing.T) {
	existing := []string{"NO_VALUE"}
	env := skexec.BuildEnv(nil, existing, "", nil)
	assert.Contains(t, env, "NO_VALUE")
}

func TestBuildEnv_CycleDetection(t *testing.T) {
	secrets := []*provider.Secret{
		{Key: "A", Value: "${B}"},
		{Key: "B", Value: "${A}"},
	}
	env := skexec.BuildEnv(secrets, nil, "", nil)

	// Should break cycle and return some value containing the reference
	// Map iteration is random, so it could be A=${B}, B=${B} OR B=${A}, A=${A}
	foundA := false
	foundB := false
	for _, e := range env {
		if e == "A=${B}" || e == "A=${A}" {
			foundA = true
		}
		if e == "B=${A}" || e == "B=${B}" {
			foundB = true
		}
	}
	assert.True(t, foundA, "A should be present with some value")
	assert.True(t, foundB, "B should be present with some value")
}

func TestBuildEnv_DeepDependency(t *testing.T) {
	secrets := []*provider.Secret{
		{Key: "V1", Value: "base"},
		{Key: "V2", Value: "${V1}"},
		{Key: "V3", Value: "${V2}"},
		{Key: "V4", Value: "${V3}"},
		{Key: "V5", Value: "${V4}"},
		{Key: "V6", Value: "${V5}"},
		{Key: "V7", Value: "${V6}"},
		{Key: "V8", Value: "${V7}"},
		{Key: "V9", Value: "${V8}"},
		{Key: "V10", Value: "${V9}"},
		{Key: "V11", Value: "${V10}"},
		{Key: "V12", Value: "${V11}"},
	}
	env := skexec.BuildEnv(secrets, nil, "", nil)

	assert.Contains(t, env, "V12=base")
}

func TestBuildEnv_Sanitization(t *testing.T) {
	secrets := []*provider.Secret{
		{Key: "NULL_BYTE", Value: "val\x00injected"},
		{Key: "NEWLINE", Value: "val\ninjected"},
		{Key: "CARRIAGE_RETURN", Value: "val\rinjected"},
	}
	env := skexec.BuildEnv(secrets, nil, "", nil)

	assert.Contains(t, env, "NULL_BYTE=valinjected")
	assert.Contains(t, env, "NEWLINE=val injected")
	assert.Contains(t, env, "CARRIAGE_RETURN=valinjected")
}

func TestKeyToEnvName_Sanitization(t *testing.T) {
	assert.Equal(t, "BAD_KEY", skexec.KeyToEnvName("BAD\nKEY", ""))
	assert.Equal(t, "BAD_KEY", skexec.KeyToEnvName("BAD=KEY", ""))
	assert.Equal(t, "BAD_KEY", skexec.KeyToEnvName("BAD KEY", ""))
}
