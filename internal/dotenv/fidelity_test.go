// internal/dotenv/fidelity_test.go
package dotenv

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fidelityCorpus is the shared adversarial value set. Keep in sync with the
// copies in internal/template and internal/cli (data, not logic).
func fidelityCorpus() []struct{ Name, Value string } {
	return []struct{ Name, Value string }{
		{"bcrypt", `$2a$14$abcdefghijklmnopqrstuv`},
		{"shell_var", `$HOME`},
		{"brace_ref", `${REF}`},
		{"double_dollar", `$$literal`},
		{"assignment", `key=value`},
		{"double_assign", `a=b=c`},
		{"newline", "line1\nline2"},
		{"crlf", "crlf\r\nend"},
		{"trailing_nl", "trailing\n"},
		{"double_quote", `he said "hi"`},
		{"single_quote", `it's`},
		{"backtick", "`backtick`"},
		{"mixed_quotes", "\"'`"},
		{"backslash", `a\b\c`},
		{"backslash_n", `\n`},
		{"leading_ws", `  leading`},
		{"trailing_ws", `trailing  `},
		{"all_space", `   `},
		{"tab", "a\tb"},
		{"unicode", `café 日本語 🔐`},
		{"empty", ``},
		{"pem", "-----BEGIN KEY-----\nabc\ndef\n-----END KEY-----"},
		{"jwt", `eyJ.eyJ.sig`},
		{"pg_url", `postgres://u:p$w@h:5432/db`},
		{"regex_special", `a.*b[c]$d`},
		{"control", "bell\actl\x01\x02"},
		{"long", string(make([]byte, 10000))}, // 10KB of NUL-free zeros replaced below
	}
}

func TestDotenv_RoundTrip_Corpus(t *testing.T) {
	for _, tc := range fidelityCorpus() {
		if tc.Name == "long" {
			tc.Value = ""
			for i := 0; i < 10000; i++ {
				tc.Value += "x"
			}
		}
		t.Run(tc.Name, func(t *testing.T) {
			line := Encode("KEY", tc.Value)
			k, v, ok := Decode(line)
			require.True(t, ok, "Decode failed for encoded %q", line)
			assert.Equal(t, "KEY", k)
			assert.Equal(t, tc.Value, v, "dotenv round-trip must be byte-exact")
		})
	}
}
