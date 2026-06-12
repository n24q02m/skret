package template

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRender_Substitutes(t *testing.T) {
	secrets := map[string]string{"DB_URL": "postgres://x", "TOKEN": "abc"}
	out, missing := Render("url=${DB_URL} tok=${TOKEN}", secrets)
	assert.Equal(t, "url=postgres://x tok=abc", out)
	assert.Empty(t, missing)
}

func TestRender_BracesOnly_LeavesBareDollar(t *testing.T) {
	secrets := map[string]string{"HOST": "h"}
	out, missing := Render("server ${HOST}; proxy $host; path $PATH", secrets)
	assert.Equal(t, "server h; proxy $host; path $PATH", out)
	assert.Empty(t, missing)
}

func TestRender_InvalidRefsLeftLiteral(t *testing.T) {
	out, missing := Render("a ${1BAD} b ${has space} c $${ESCAPED}", map[string]string{})
	assert.Equal(t, "a ${1BAD} b ${has space} c ${ESCAPED}", out)
	assert.Empty(t, missing)
}

func TestRender_EscapeDollar(t *testing.T) {
	out, missing := Render("price=$$5 literal=$${TOKEN}", map[string]string{"TOKEN": "should-not-be-used"})
	assert.Equal(t, "price=$5 literal=${TOKEN}", out)
	assert.Empty(t, missing)
}

func TestRender_MissingKeys_DedupedSorted(t *testing.T) {
	out, missing := Render("${B} ${A} ${B} ${A_OK}", map[string]string{"A_OK": "v"})
	assert.Equal(t, "${B} ${A} ${B} v", out)
	assert.Equal(t, []string{"A", "B"}, missing)
}

func TestRender_Empty(t *testing.T) {
	out, missing := Render("", map[string]string{"X": "y"})
	assert.Equal(t, "", out)
	assert.Empty(t, missing)
}

func TestRender_AdjacentRefs(t *testing.T) {
	out, missing := Render("${A}${B}", map[string]string{"A": "1", "B": "2"})
	assert.Equal(t, "12", out)
	assert.Empty(t, missing)
}
