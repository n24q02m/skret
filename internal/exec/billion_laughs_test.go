package exec_test

import (
	"fmt"
	skexec "github.com/n24q02m/skret/internal/exec"
	"github.com/n24q02m/skret/internal/provider"
	"github.com/stretchr/testify/assert"
	"testing"
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

func TestBuildEnv_DepthLimitHit(t *testing.T) {
	// Create a chain of 100 secrets. Even with random iteration, it's very likely to hit depth 32.
	var secrets []*provider.Secret
	secrets = append(secrets, &provider.Secret{Key: "V0", Value: "base"})
	for i := 1; i <= 100; i++ {
		secrets = append(secrets, &provider.Secret{
			Key:   fmt.Sprintf("V%d", i),
			Value: fmt.Sprintf("${V%d}", i-1),
		})
	}

	env := skexec.BuildEnv(secrets, nil, "", nil)
	assert.NotEmpty(t, env)
}

func TestBuildEnv_LengthLimit(t *testing.T) {
	// Let's create an expansion that exceeds maxExpandedLen but doesn't hit depth limit
	base := ""
	for i := 0; i < 4000; i++ {
		base += "A"
	}
	var secrets []*provider.Secret
	secrets = append(secrets, &provider.Secret{Key: "V0", Value: base})
	for i := 1; i <= 6; i++ { // depth=6, each step multiples length by 2 -> 4000 * 2^6 = 256,000 > 131,072 limit
		secrets = append(secrets, &provider.Secret{
			Key:   fmt.Sprintf("V%d", i),
			Value: fmt.Sprintf("${V%d}${V%d}", i-1, i-1),
		})
	}

	env := skexec.BuildEnv(secrets, nil, "", nil)
	assert.NotEmpty(t, env)

	found := false
	for _, e := range env {
		if len(e) > 3 && e[:3] == "V6=" {
			found = true
			val := e[3:]
			assert.Equal(t, 128*1024, len(val), "Length should be exactly truncated to limit")
		}
	}
	assert.True(t, found, "V6 should be present in output")
}
