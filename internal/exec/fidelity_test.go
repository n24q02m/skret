package exec

import (
	"testing"

	"github.com/n24q02m/skret/internal/provider"
	"github.com/stretchr/testify/assert"
)

func TestBuildEnv_ByteExact_NoExpansion(t *testing.T) {
	cases := map[string]string{
		"bcrypt": `$2a$14$x`, "ref": `${HOME}`, "assign": `a=b`,
		"pg": `postgres://u:p$w@h/db`, "dollar_word": `$word`,
	}
	for name, val := range cases {
		t.Run(name, func(t *testing.T) {
			env := BuildEnv([]*provider.Secret{{Key: "/a/dev/K", Value: val}}, nil, "/a/dev", nil)
			var got string
			found := false
			for _, e := range env {
				if len(e) >= 2 && e[:2] == "K=" {
					got = e[2:]
					found = true
				}
			}
			assert.True(t, found, "K must be injected")
			assert.Equal(t, val, got, "BuildEnv must inject the value verbatim (no $-expansion)")
		})
	}
}
