package exec_test

import (
	"strings"
	"testing"

	skexec "github.com/n24q02m/skret/internal/exec"
	"github.com/n24q02m/skret/internal/provider"
	"github.com/stretchr/testify/assert"
)

// TestBuildEnv_ByteExactPreservation verifies that values are injected verbatim:
// no shell-style expansion and no silent truncation. (The previous expansion
// length cap is gone now that values are never expanded.)
func TestBuildEnv_ByteExactPreservation(t *testing.T) {
	t.Run("RefLikeValuesNotExpanded", func(t *testing.T) {
		// Values that previously would have caused exponential expansion are now
		// kept exactly as stored.
		secrets := []*provider.Secret{
			{Key: "V1", Value: "a"},
			{Key: "V2", Value: "${V1}${V1}"},
			{Key: "V3", Value: "${V2}${V2}"},
		}
		env := skexec.BuildEnv(secrets, nil, "", nil)
		assert.Contains(t, env, "V2=${V1}${V1}")
		assert.Contains(t, env, "V3=${V2}${V2}")
	})

	t.Run("LargeValueNotTruncated", func(t *testing.T) {
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
		assert.Equal(t, 200*1024, len(longVal), "value must be injected without truncation")
	})

	t.Run("DollarHeavyValuePreserved", func(t *testing.T) {
		val := "$$$${a}$b$c$2a$14$xyz"
		secrets := []*provider.Secret{
			{Key: "DOLLARS", Value: val},
		}
		env := skexec.BuildEnv(secrets, nil, "", nil)
		assert.Contains(t, env, "DOLLARS="+val)
	})
}
