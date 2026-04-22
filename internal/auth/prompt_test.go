package auth_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/n24q02m/skret/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfirm_YesDefault(t *testing.T) {
	for _, in := range []string{"y\n", "Y\n", "yes\n", "\n"} {
		var out bytes.Buffer
		ok := auth.Confirm(strings.NewReader(in), &out, "proceed?")
		assert.True(t, ok, "input %q should confirm", in)
	}
}

func TestConfirm_No(t *testing.T) {
	var out bytes.Buffer
	ok := auth.Confirm(strings.NewReader("n\n"), &out, "proceed?")
	assert.False(t, ok)
}

func TestConfirm_NoResponse(t *testing.T) {
	var out bytes.Buffer
	ok := auth.Confirm(strings.NewReader("no\n"), &out, "proceed?")
	assert.False(t, ok)
}

func TestSelectMethod_PicksIndex(t *testing.T) {
	var out bytes.Buffer
	methods := []auth.Method{
		{Name: "sso", Description: "AWS SSO device flow"},
		{Name: "access-key", Description: "Access key + secret key"},
		{Name: "assume-role", Description: "Assume IAM role"},
	}
	m, err := auth.SelectMethod(strings.NewReader("2\n"), &out, methods)
	require.NoError(t, err)
	assert.Equal(t, "access-key", m.Name)
}

func TestSelectMethod_InvalidIndex(t *testing.T) {
	var out bytes.Buffer
	methods := []auth.Method{{Name: "sso"}}
	_, err := auth.SelectMethod(strings.NewReader("5\n"), &out, methods)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid choice")
}

func TestSelectMethod_NotANumber(t *testing.T) {
	var out bytes.Buffer
	methods := []auth.Method{{Name: "sso"}}
	_, err := auth.SelectMethod(strings.NewReader("abc\n"), &out, methods)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid choice")
}

func TestSelectMethod_EmptyDescription(t *testing.T) {
	var out bytes.Buffer
	methods := []auth.Method{{Name: "sso"}}
	m, err := auth.SelectMethod(strings.NewReader("1\n"), &out, methods)
	require.NoError(t, err)
	assert.Equal(t, "sso", m.Name)
	// When description is empty, should use name as fallback
	assert.Contains(t, out.String(), "sso")
}
