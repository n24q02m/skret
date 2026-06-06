package exec_test

import (
	"fmt"
	"testing"

	skexec "github.com/n24q02m/skret/internal/exec"
	"github.com/n24q02m/skret/internal/provider"
	"github.com/stretchr/testify/assert"
)

func TestBuildEnv_BillionLaughs(t *testing.T) {
	var secrets []*provider.Secret
	secrets = append(secrets, &provider.Secret{Key: "V0", Value: "base"})
	for i := 1; i <= 32; i++ {
		secrets = append(secrets, &provider.Secret{
			Key:   fmt.Sprintf("V%d", i),
			Value: fmt.Sprintf("${V%d}${V%d}", i-1, i-1),
		})
	}

	env := skexec.BuildEnv(secrets, nil, "", nil)
	assert.NotEmpty(t, env)

	// Find V32 and check its length. Without limits it would be 2^32 * 4 = ~17GB string
	// Or it would exceed limit and cause OOM.
	// With the limit, it should be limited.
	found := false
	for _, e := range env {
		if len(e) > 4 && e[:4] == "V32=" {
			found = true
			val := e[4:]
			assert.LessOrEqual(t, len(val), 128*1024, "Length should be limited")
		}
	}
	assert.True(t, found, "V32 should be present in output")
}
