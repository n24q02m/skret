package exec_test

import (
	"testing"

	skexec "github.com/n24q02m/skret/internal/exec"
	"github.com/n24q02m/skret/internal/provider"
	"github.com/stretchr/testify/assert"
)

// TestBuildEnv_DollarValuesByteExact is the regression for the corruption bug:
// secret values containing '$' (bcrypt hashes, URLs with passwords) MUST be
// injected verbatim, never run through shell-style expansion.
func TestBuildEnv_DollarValuesByteExact(t *testing.T) {
	bcrypt := "$2a$14$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
	pgURL := "postgres://u:p$word@host/db"
	secrets := []*provider.Secret{
		{Key: "HASH", Value: bcrypt},
		{Key: "PGURL", Value: pgURL},
		{Key: "BRACED", Value: "literal-${NOT_A_REF}-kept"},
		{Key: "DOUBLE", Value: "price-$$100"},
	}
	env := skexec.BuildEnv(secrets, nil, "", nil)

	assert.Contains(t, env, "HASH="+bcrypt)
	assert.Contains(t, env, "PGURL="+pgURL)
	assert.Contains(t, env, "BRACED=literal-${NOT_A_REF}-kept")
	assert.Contains(t, env, "DOUBLE=price-$$100")
}

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
	env2 := skexec.BuildEnv([]*provider.Secret{}, []string{"HOME=/root"}, "", nil)
	assert.Equal(t, []string{"HOME=/root"}, env2)
}

func TestKeyToEnvName_NoPrefix(t *testing.T) {
	assert.Equal(t, "DB_URL", skexec.KeyToEnvName("DB_URL", ""))
	assert.Equal(t, "API_KEY", skexec.KeyToEnvName("api_key", ""))
}

func TestKeyToEnvName_HyphenToUnderscore(t *testing.T) {
	// Hyphens are not valid in POSIX env var names; normalize them to "_"
	// so a key like "api-key" yields the usable env var "API_KEY".
	assert.Equal(t, "API_KEY", skexec.KeyToEnvName("api-key", ""))
	assert.Equal(t, "MY_APP_KEY", skexec.KeyToEnvName("my-app-key", ""))
	assert.Equal(t, "API_KEY", skexec.KeyToEnvName("/app/prod/api-key", "/app/prod"))
	assert.Equal(t, "A_B_C_D", skexec.KeyToEnvName("/x/a-b/c-d", "/x"))
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

func TestBuildEnv_SecretRefKeptLiteral(t *testing.T) {
	secrets := []*provider.Secret{
		{Key: "A", Value: "1"},
		{Key: "B", Value: "${A}"},
	}
	existing := []string{}

	env := skexec.BuildEnv(secrets, existing, "", nil)

	assert.Contains(t, env, "B=${A}")
}

func TestBuildEnv_ExistingRefKeptLiteral(t *testing.T) {
	secrets := []*provider.Secret{
		{Key: "B", Value: "${A}"},
	}
	existing := []string{"A=2"}

	env := skexec.BuildEnv(secrets, existing, "", nil)

	assert.Contains(t, env, "B=${A}")
}

func TestBuildEnv_SecretHostEnvRefKeptLiteral(t *testing.T) {
	t.Setenv("HOST_ENV", "host_value")
	secrets := []*provider.Secret{
		{Key: "DB_PASS", Value: "${HOST_ENV}"},
	}
	existing := []string{}

	env := skexec.BuildEnv(secrets, existing, "", nil)

	assert.Contains(t, env, "DB_PASS=${HOST_ENV}")
}

func TestBuildEnv_ExistingNoValue(t *testing.T) {
	existing := []string{"NO_VALUE"}
	env := skexec.BuildEnv(nil, existing, "", nil)
	assert.Contains(t, env, "NO_VALUE")
}

func TestBuildEnv_MutualRefsKeptLiteral(t *testing.T) {
	secrets := []*provider.Secret{
		{Key: "A", Value: "${B}"},
		{Key: "B", Value: "${A}"},
	}
	env := skexec.BuildEnv(secrets, nil, "", nil)

	// No expansion: each value is injected exactly as stored.
	assert.Contains(t, env, "A=${B}")
	assert.Contains(t, env, "B=${A}")
}

func TestBuildEnv_DeepRefChainKeptLiteral(t *testing.T) {
	secrets := []*provider.Secret{
		{Key: "V1", Value: "base"},
		{Key: "V2", Value: "${V1}"},
		{Key: "V12", Value: "${V11}"},
	}
	env := skexec.BuildEnv(secrets, nil, "", nil)

	assert.Contains(t, env, "V1=base")
	assert.Contains(t, env, "V2=${V1}")
	assert.Contains(t, env, "V12=${V11}")
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

func TestBuildEnv_EmptyExcludeMap(t *testing.T) {
	secrets := []*provider.Secret{
		{Key: "A", Value: "1"},
	}
	existing := []string{"B=2"}
	env := skexec.BuildEnv(secrets, existing, "", []string{})
	assert.Contains(t, env, "A=1")
	assert.Contains(t, env, "B=2")
}
