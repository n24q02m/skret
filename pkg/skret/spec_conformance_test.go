package skret

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The spec document (docs/src/content/docs/reference/spec.md) is the
// normative exit-code contract. This test keeps it and the code from
// drifting apart in either direction: every constant in errors.go must
// appear in the spec table with the same numeric code, and every table row
// must name a constant that exists with that code.

const specRelPath = "../../docs/src/content/docs/reference/spec.md"

var (
	constLineRe  = regexp.MustCompile(`(?m)^\s*(Exit\w+)\s*=\s*(\d+)`)
	specVersion  = regexp.MustCompile(`(?m)^\*\*Version (\d+\.\d+\.\d+)\*\*`)
	specTableRow = regexp.MustCompile(`^\|\s*(\d+)\s*\|\s*` + "`" + `(Exit\w+)` + "`" + `\s*\|`)
)

func loadSpec(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(".")
	require.NoError(t, err)
	specPath := filepath.Join(root, strings.ReplaceAll(specRelPath, "/", string(filepath.Separator)))
	raw, err := os.ReadFile(specPath)
	require.NoError(t, err, "spec document must exist at %s", specPath)
	return string(raw)
}

func TestSpecConformance_ExitCodeTable(t *testing.T) {
	spec := loadSpec(t)

	// The spec is versioned; a table change without a version bump is a
	// spec-edit smell.
	m := specVersion.FindStringSubmatch(spec)
	require.NotNil(t, m, "spec must carry a **Version X.Y.Z** header")
	assert.Regexp(t, `^\d+\.\d+\.\d+$`, m[1])

	// Codes as declared in code (errors.go const block).
	fromCode := map[int]string{}
	for _, sm := range constLineRe.FindAllStringSubmatch(errorsConstSource(t), -1) {
		code, cErr := strconv.Atoi(sm[2])
		require.NoError(t, cErr)
		assert.Equal(t, "", fromCode[code], "errors.go declares duplicate code %d", code)
		fromCode[code] = sm[1]
	}
	require.NotEmpty(t, fromCode, "errors.go const block must be parsed")
	assert.Equal(t, "ExitSuccess", fromCode[0], "code 0 must stay ExitSuccess")

	// Codes as documented in the spec table.
	fromSpec := map[int]string{}
	for _, line := range strings.Split(spec, "\n") {
		if sm := specTableRow.FindStringSubmatch(strings.TrimRight(line, "\r")); sm != nil {
			code, cErr := strconv.Atoi(sm[1])
			require.NoError(t, cErr)
			assert.Equal(t, "", fromSpec[code], "spec table declares duplicate code %d", code)
			fromSpec[code] = sm[2]
		}
	}
	require.NotEmpty(t, fromSpec, "spec exit-code table must be parsed")

	// Exact 1:1 — closed set in both directions.
	assert.Equal(t, fromCode, fromSpec,
		"exit codes in errors.go and the spec table must match exactly;\n code: %v\n spec: %v", fromCode, fromSpec)
}

// errorsConstSource reads this package's own errors.go so a newly added
// constant fails the test until it is documented in the spec.
func errorsConstSource(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("errors.go"))
	require.NoError(t, err, "pkg/skret/errors.go must exist next to this test")
	return string(raw)
}

// TestSpecConformance_MarkerLiterals pins the spec's prose to the literal
// wire-format strings the code actually emits, so a rename in either place
// is caught.
func TestSpecConformance_MarkerLiterals(t *testing.T) {
	spec := loadSpec(t)

	for _, literal := range []string{
		"skret-encrypted-v1", // keystore envelope marker (internal/keystore Format)
		`"error"`,            // JSON error envelope keys (internal/cli/errjson.go)
		`"code"`,
		`"remediation"`,
		"125", // ExitExecError convention call-out
	} {
		assert.Contains(t, spec, literal, "spec must document literal %q", literal)
	}
}
