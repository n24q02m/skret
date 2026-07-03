// internal/template/fidelity_test.go
package template

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRender_ValueByteExact_NoReExpand(t *testing.T) {
	cases := []struct{ name, value string }{
		{"bcrypt", `$2a$14$x`},
		{"brace_ref_in_value", `${OTHER}`},
		{"dollar", `a$b`},
		{"newline", "l1\nl2"},
		{"quotes", `"'`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, missing := Render("${K}", map[string]string{"K": c.value})
			assert.Empty(t, missing)
			assert.Equal(t, c.value, out, "substituted value must be literal, not re-expanded")
		})
	}
	// escape: $${K} renders literal ${K}, never substituted
	out, _ := Render("$${K}", map[string]string{"K": "v"})
	assert.Equal(t, "${K}", out)
}
