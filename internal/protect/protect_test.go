package protect

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Fabricated token-shaped strings, assembled at run time so this file does
// not itself contain anything a secret scanner would flag.
func fakeToken(prefix, alphabet string, n int) string {
	return prefix + strings.Repeat(alphabet, n/len(alphabet)+1)[:n]
}

func fakeTokens() map[string]string {
	return map[string]string{
		"github-pat":                  fakeToken("ghp_", "aB3d", 36),
		"github-token":                fakeToken("gho_", "aB3d", 36),
		"github-fine-grained-pat":     fakeToken("github_pat_", "aB3d", 22) + "_" + fakeToken("", "Xy9z", 59),
		"aws-access-key-id":           fakeToken("AKIA", "QZ7X", 16),
		"aws-temporary-access-key-id": fakeToken("ASIA", "QZ7X", 16),
		"sk-api-key":                  fakeToken("sk-", "aB3d", 24),
		"sk-scoped-api-key":           fakeToken("sk-proj-", "aB3d_", 48),
		"doppler-service-token":       fakeToken("dp.st.", "aB3d", 40),
		"slack-token":                 fakeToken("xoxb-", "1234-", 30),
		"slack-webhook":               "https://hooks.slack.com/services/" + fakeToken("T", "0A", 8) + "/" + fakeToken("B", "0A", 8) + "/" + fakeToken("", "aB3d", 24),
		"stripe-live-key":             fakeToken("sk_live_", "aB3d", 24),
		"google-api-key":              fakeToken("AIza", "aB3d_-", 35),
		"gitlab-pat":                  fakeToken("glpat-", "aB3d", 20),
		"npm-token":                   fakeToken("npm_", "aB3d", 36),
		"pypi-token":                  fakeToken("pypi-AgEIcHlwaS5vcmc", "aB3d", 60),
		"private-key":                 "-----BEGIN " + "OPENSSH PRIVATE KEY-----",
		"age-secret-key":              fakeToken("AGE-SECRET-KEY-1", "QPZRY9X8", 58),
	}
}

func newChecker(t *testing.T, opts Options) *Checker {
	t.Helper()
	c, err := New(opts)
	require.NoError(t, err)
	return c
}

func TestCheck_DetectsEveryTokenFormat(t *testing.T) {
	c := newChecker(t, Options{})
	for rule, token := range fakeTokens() {
		t.Run(rule, func(t *testing.T) {
			content := "first line\nconfig: " + token + " # trailing\n"
			findings := c.Check("src/settings.yaml", []byte(content))
			require.Len(t, findings, 1, "findings: %+v", findings)
			assert.Equal(t, Finding{File: "src/settings.yaml", Line: 2, Rule: rule}, findings[0])
		})
	}
}

func TestCheck_EveryRuleIsTested(t *testing.T) {
	tested := fakeTokens()
	for _, name := range newChecker(t, Options{}).RuleNames() {
		if name == EnvFileRule {
			continue
		}
		_, ok := tested[name]
		assert.True(t, ok, "rule %q has no detection test", name)
	}
}

func TestCheck_CleanContent(t *testing.T) {
	c := newChecker(t, Options{})
	content := strings.Join([]string{
		"package main",
		`const greeting = "hello"`,
		"commit 0123456789abcdef0123456789abcdef01234567",
		"h1:" + strings.Repeat("Ab+/", 11) + "=",
		"password=${DB_PASS}",
		"ghp_short",
		"task-" + strings.Repeat("a", 30),
	}, "\n")
	assert.Empty(t, c.Check("main.go", []byte(content)))
}

func TestCheck_StrictAddsGenericRules(t *testing.T) {
	content := []byte("db: password=hunter2-fixture\nblob: " + strings.Repeat("Ab3d", 12) + "\n")
	assert.Empty(t, newChecker(t, Options{}).Check("app.conf", content))

	findings := newChecker(t, Options{Strict: true}).Check("app.conf", content)
	assert.Equal(t, []Finding{
		{File: "app.conf", Line: 1, Rule: "secret-assignment"},
		{File: "app.conf", Line: 2, Rule: "base64-blob"},
	}, findings)
}

func TestCheck_EnvFiles(t *testing.T) {
	c := newChecker(t, Options{})
	flagged := []string{
		".env", ".env.local", ".env.production", ".env-dev", ".env_test",
		"prod.env", "config/.env", "APP.ENV",
	}
	for _, name := range flagged {
		assert.Equal(t, []Finding{{File: name, Line: 0, Rule: EnvFileRule}}, c.Check(name, []byte("A=1\n")), name)
	}
	clean := []string{
		".env.example", ".env.sample", ".env.template", ".env.dist", "app.env.example",
		".envrc", "env.go", "environment.yaml", "dotenv.md", ".environment",
	}
	for _, name := range clean {
		assert.Empty(t, c.Check(name, []byte("A=1\n")), name)
	}
}

// Templates are allowed by name, but a real token inside one is still caught.
func TestCheck_TemplatesAreStillScanned(t *testing.T) {
	c := newChecker(t, Options{})
	findings := c.Check(".env.example", []byte("GITHUB_TOKEN="+fakeTokens()["github-pat"]+"\n"))
	assert.Equal(t, []Finding{{File: ".env.example", Line: 1, Rule: "github-pat"}}, findings)
}

// An env file with no readable content (binary, oversize, symlink) is still
// flagged by name.
func TestCheck_EnvFileWithoutContent(t *testing.T) {
	c := newChecker(t, Options{})
	assert.Equal(t, []Finding{{File: ".env", Line: 0, Rule: EnvFileRule}}, c.Check(".env", nil))
	assert.Empty(t, c.Check("notes.txt", nil))
}

func TestCheck_AllowPatterns(t *testing.T) {
	token := fakeTokens()["github-pat"]
	c := newChecker(t, Options{Allow: []string{"*.fixture", "testdata/", "docs/*.md", ".env.ci"}})
	allowed := []string{"keys.fixture", "a/b/keys.fixture", "testdata/x.txt", "pkg/testdata/deep/x.txt", "docs/guide.md", ".env.ci"}
	for _, name := range allowed {
		assert.Empty(t, c.Check(name, []byte(token)), name)
	}
	notAllowed := []string{"keys.txt", "mytestdata/x.txt", "docs/sub/guide.md", "src/docs/guide.md"}
	for _, name := range notAllowed {
		assert.NotEmpty(t, c.Check(name, []byte(token)), name)
	}
	// Allowed answers the same question for callers that skip a file before
	// reading it; OS path separators are accepted.
	assert.True(t, c.Allowed(filepath.Join("pkg", "testdata", "x.txt")))
	assert.True(t, c.Allowed("a/b/keys.fixture"))
	assert.False(t, c.Allowed("keys.txt"))
}

func TestKnownBinary(t *testing.T) {
	for _, name := range []string{"logo.PNG", "assets/photo.jpeg", "font.woff2", "manual.pdf", "lib/app.dll", "mod.wasm", "clip.mp4"} {
		assert.True(t, KnownBinary(name), name)
	}
	// Archives and databases can hold text that protect cannot read, and
	// anything else may be text the NUL check misjudged, so none of these
	// is known to be safe to skip.
	for _, name := range []string{"bundle.zip", "backup.tar.gz", "app.jar", "data.sqlite", "dump.log", "notes", ".png.txt"} {
		assert.False(t, KnownBinary(name), name)
	}
}

func TestNew_RejectsBadAllowPattern(t *testing.T) {
	_, err := New(Options{Allow: []string{"[unclosed"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"[unclosed"`)
}

func TestCheck_InlineAllowMarker(t *testing.T) {
	c := newChecker(t, Options{})
	token := fakeTokens()["aws-access-key-id"]
	content := "key: " + token + " # " + AllowMarker + "\nother: " + token + "\n"
	assert.Equal(t, []Finding{{File: "f.yaml", Line: 2, Rule: "aws-access-key-id"}}, c.Check("f.yaml", []byte(content)))
}

// One finding per rule per line, however many matches the line holds, and
// several rules on one line each report.
func TestCheck_OneFindingPerRulePerLine(t *testing.T) {
	c := newChecker(t, Options{})
	tokens := fakeTokens()
	line := tokens["github-pat"] + " " + tokens["github-pat"] + " " + tokens["npm-token"]
	assert.Equal(t, []Finding{
		{File: "f", Line: 1, Rule: "github-pat"},
		{File: "f", Line: 1, Rule: "npm-token"},
	}, c.Check("f", []byte(line)))
}

func TestCheck_CRLFAndLastLineWithoutNewline(t *testing.T) {
	c := newChecker(t, Options{})
	content := "a\r\nb\r\n" + fakeTokens()["gitlab-pat"]
	assert.Equal(t, []Finding{{File: "f", Line: 3, Rule: "gitlab-pat"}}, c.Check("f", []byte(content)))
}

func TestSort(t *testing.T) {
	findings := []Finding{
		{File: "b", Line: 1, Rule: "x"},
		{File: "a", Line: 2, Rule: "y"},
		{File: "a", Line: 2, Rule: "a"},
		{File: "a", Line: 0, Rule: EnvFileRule},
	}
	Sort(findings)
	assert.Equal(t, []Finding{
		{File: "a", Line: 0, Rule: EnvFileRule},
		{File: "a", Line: 2, Rule: "a"},
		{File: "a", Line: 2, Rule: "y"},
		{File: "b", Line: 1, Rule: "x"},
	}, findings)
}

func TestRender(t *testing.T) {
	findings := []Finding{{File: ".env", Line: 0, Rule: EnvFileRule}, {File: "a.txt", Line: 3, Rule: "github-pat"}}

	var table bytes.Buffer
	require.NoError(t, RenderTable(&table, findings))
	assert.Equal(t, "FILE   LINE  RULE\n.env   -     env-file\na.txt  3     github-pat\n", table.String())

	var js bytes.Buffer
	require.NoError(t, RenderJSON(&js, findings))
	var decoded []Finding
	require.NoError(t, json.Unmarshal(js.Bytes(), &decoded))
	assert.Equal(t, findings, decoded)

	js.Reset()
	require.NoError(t, RenderJSON(&js, nil))
	assert.Equal(t, "[]\n", js.String())
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, assert.AnError }

func TestRender_WriteErrors(t *testing.T) {
	findings := []Finding{{File: "a", Line: 1, Rule: "r"}}
	require.ErrorIs(t, RenderTable(failWriter{}, findings), assert.AnError)
	require.ErrorIs(t, RenderJSON(failWriter{}, findings), assert.AnError)
}

// Findings never carry the matched text, whatever the rule.
func TestFindingNeverHoldsTheSecret(t *testing.T) {
	c := newChecker(t, Options{Strict: true})
	for _, token := range fakeTokens() {
		var out bytes.Buffer
		findings := c.Check("f", []byte("x "+token+"\n"))
		require.NoError(t, RenderTable(&out, findings))
		require.NoError(t, RenderJSON(&out, findings))
		assert.NotContains(t, out.String(), token)
	}
}
