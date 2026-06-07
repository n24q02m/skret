package importer

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUnquote(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{`"quoted"`, "quoted"},
		{`'single'`, "single"},
		{"`backtick`", "backtick"},
		{`no quotes`, "no quotes"},
		{`"mismatched'`, `"mismatched'`},
		{`'mismatched"`, `'mismatched"`},
		{"`mismatched\"", "`mismatched\""},
		{`""`, ""},
		{`''`, ""},
		{"``", ""},
		{`a`, "a"},
		{``, ""},
		{`"one char"`, "one char"},
		{`"nested 'quotes'"`, "nested 'quotes'"},
		{`'nested "quotes"'`, "nested \"quotes\""},
		{"`nested 'single' and \"double\" quotes`", "nested 'single' and \"double\" quotes"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, unquote(tt.input))
		})
	}
}


// Trivial change to force CI re-run
