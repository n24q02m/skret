package exec_test

import (
	"fmt"
	"strings"
	"testing"

	skexec "github.com/n24q02m/skret/internal/exec"
	"github.com/n24q02m/skret/internal/provider"
	"github.com/stretchr/testify/assert"
)

func TestBuildEnv_ExpansionLimits(t *testing.T) {
	t.Run("ExponentialGrowth", func(t *testing.T) {
		// A=${B}${B}, B=${C}${C}, ...
		// This would normally cause exponential growth in string length.
		secrets := []*provider.Secret{
			{Key: "V1", Value: "a"},
		}
		for i := 2; i <= 20; i++ {
			secrets = append(secrets, &provider.Secret{
				Key:   fmt.Sprintf("V%d", i),
				Value: fmt.Sprintf("${V%d}${V%d}", i-1, i-1),
			})
		}

		env := skexec.BuildEnv(secrets, nil, "", nil)

		// Find V20
		var v20 string
		for _, e := range env {
			if strings.HasPrefix(e, "V20=") {
				v20 = e[4:]
				break
			}
		}

		// 2^19 * 1 = 524288, which is > 128KB (131072)
		// It should be truncated to exactly 128KB
		assert.Equal(t, 128*1024, len(v20))
	})

	t.Run("SingleLongString", func(t *testing.T) {
		val := strings.Repeat("a", 200*1024)
		secrets := []*provider.Secret{
			{Key: "LONG", Value: val},
		}
		env := skexec.BuildEnv(secrets, nil, "", nil)
		var longVal string
		for _, e := range env {
			if strings.HasPrefix(e, "LONG=") {
				longVal = e[5:]
				break
			}
		}
		assert.Equal(t, 128*1024, len(longVal))
	})

	t.Run("DeepRecursionProtection", func(t *testing.T) {
		// Verify that a very deep chain doesn't cause a crash (stack overflow).
		assert.NotPanics(t, func() {
			bigSecrets := []*provider.Secret{}
			for i := 1; i < 2000; i++ {
				bigSecrets = append(bigSecrets, &provider.Secret{
					Key:   fmt.Sprintf("X%d", i),
					Value: fmt.Sprintf("${X%d}", i+1),
				})
			}
			bigSecrets = append(bigSecrets, &provider.Secret{Key: "X2000", Value: "base"})
			skexec.BuildEnv(bigSecrets, nil, "", nil)
		})
	})
}
