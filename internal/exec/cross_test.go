package exec_test

import (
        "os"
        "testing"

        skexec "github.com/n24q02m/skret/internal/exec"
        "github.com/n24q02m/skret/internal/provider"
        "github.com/stretchr/testify/assert"
)

func TestBuildEnv_CrossReference(t *testing.T) {
        secrets := []*provider.Secret{
                {Key: "DB_USER", Value: "admin"},
                {Key: "DB_PASS", Value: "supersecret"},
                {Key: "DB_URL", Value: "postgres://${DB_USER}:${DB_PASS}@localhost"},
                {Key: "DB_CONNECTION", Value: "connected to ${DB_URL}"},
        }

        os.Setenv("TEST_REGION", "us-east-1")
        defer os.Unsetenv("TEST_REGION")

        secretsWithOsEnv := append(secrets, &provider.Secret{Key: "TEST_INFO", Value: "region=${TEST_REGION}"})

        env := skexec.BuildEnv(secretsWithOsEnv, nil, "", nil)

        assert.Contains(t, env, "DB_USER=admin")
        assert.Contains(t, env, "DB_URL=postgres://admin:supersecret@localhost")
        assert.Contains(t, env, "DB_CONNECTION=connected to postgres://admin:supersecret@localhost")
        assert.Contains(t, env, "TEST_INFO=region=us-east-1")
}
