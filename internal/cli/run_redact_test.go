package cli

import (
	"encoding/base64"
	"errors"
	"net/url"
	"os"
	osexec "os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/n24q02m/skret/internal/logging"
	"github.com/n24q02m/skret/internal/redact"
	"github.com/n24q02m/skret/pkg/skret"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Fabricated values only; none of them is a real credential.
const (
	redactToken    = "redact-fixture-token-0001"
	redactPassword = "p@ss w0rd/x+y&z=fixture"
	redactPEMLine1 = "MIIfakeFIXTURElineONE0123"
	redactPEMLine2 = "MIIfakeFIXTURElineTWO4567"
)

var redactPEM = "-----BEGIN FAKE FIXTURE-----\n" + redactPEMLine1 + "\n" + redactPEMLine2 + "\n-----END FAKE FIXTURE-----"

// writeRedactConfig writes a local-provider project holding the fixture
// secrets (plus one value too short to mask by default) and the payload the
// print child writes, returning the project dir.
func writeRedactConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	indented := "    " + strings.ReplaceAll(redactPEM, "\n", "\n    ")
	files := map[string]string{
		".skret.yaml": "version: \"1\"\ndefault_env: dev\nenvironments:\n  dev:\n    provider: local\n    file: dev.yaml\n",
		"dev.yaml": "version: \"1\"\nsecrets:\n" +
			"  API_TOKEN: " + redactToken + "\n" +
			"  DB_PASS: \"" + redactPassword + "\"\n" +
			"  TLS_KEY: |-\n" + indented + "\n" +
			"  PORT: \"80\"\n",
		"payload.txt": redactPayload(),
	}
	for name, content := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600))
	}
	return dir
}

// redactPayload is what the child prints: every value in several forms, a
// token-shaped string skret does not manage, and plain text that must survive.
func redactPayload() string {
	return strings.Join([]string{
		"plain-visible-line",
		"token=" + redactToken,
		"pass: " + redactPassword,
		"b64: " + base64.StdEncoding.EncodeToString([]byte(redactPassword)),
		"b64url: " + base64.URLEncoding.EncodeToString([]byte(redactPassword)),
		"urlenc: " + url.QueryEscape(redactPassword),
		"pem:\n" + redactPEM,
		"pat: " + fakePAT(),
		"port 80 stays",
	}, "\n") + "\n"
}

func fakePAT() string { return "ghp_" + strings.Repeat("Ab12", 9) }

// redactLeaks lists every form of a secret that must never reach the output.
func redactLeaks() []string {
	return []string{
		redactToken, redactPassword, redactPEMLine1, redactPEMLine2,
		base64.StdEncoding.EncodeToString([]byte(redactPassword)),
		base64.URLEncoding.EncodeToString([]byte(redactPassword)),
		url.QueryEscape(redactPassword),
		fakePAT(),
	}
}

// runRedact runs `skret <args> -- <this test binary>` in dir; TestMain turns
// the child into a printer of payload.txt that exits with exitCode.
func runRedact(t *testing.T, dir string, exitCode int, args ...string) (string, string, error) {
	t.Helper()
	t.Setenv("SKRET_RUN_PRINT_FILE", filepath.Join(dir, "payload.txt"))
	t.Setenv("SKRET_RUN_PRINT_ENV", "TLS_KEY")
	t.Setenv("SKRET_RUN_PRINT_EXIT", strconv.Itoa(exitCode))
	chdirTmp(t, dir)
	return runRootCmd(t, append(args, "--", os.Args[0])...)
}

func TestRunRedact_MasksStdoutAndStderr(t *testing.T) {
	stdout, stderr, err := runRedact(t, writeRedactConfig(t), 0, "run", "--redact")
	require.NoError(t, err)

	// The child writes stdout one byte at a time, so every secret straddles
	// write boundaries there; stderr arrives in a single write.
	for name, out := range map[string]string{"stdout": stdout, "stderr": stderr} {
		for _, leak := range redactLeaks() {
			assert.NotContains(t, out, leak, "%s leaked a secret form", name)
		}
		assert.Contains(t, out, "plain-visible-line\n", name)
		assert.Contains(t, out, "token="+redact.Marker+"\n", name)
		assert.Contains(t, out, "pem:\n"+redact.Marker+"\n", name)
		assert.Contains(t, out, "port 80 stays\n", name, "short values are not masked by default")
	}
	// The child also echoes TLS_KEY as it sees it: the injected single-line
	// form of the multi-line value, which is masked as well.
	assert.NotContains(t, stdout, strings.ReplaceAll(redactPEM, "\n", " "))
	assert.True(t, strings.HasSuffix(stdout, "port 80 stays\n"+redact.Marker), "got %q", stdout)
}

func TestRunRedact_PreservesExitCode(t *testing.T) {
	for _, code := range []int{0, 1, 3, 42} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			stdout, _, err := runRedact(t, writeRedactConfig(t), code, "run", "--redact")
			assert.Contains(t, stdout, "plain-visible-line", "output is flushed whatever the exit code")
			assert.Equal(t, code, skret.ExitCode(err))
			if code == 0 {
				require.NoError(t, err)
				return
			}
			var exitErr *osexec.ExitError
			require.True(t, errors.As(err, &exitErr), "the child's own status is returned, got %T", err)
		})
	}
}

func TestRunRedact_WarnsAboutShortValues(t *testing.T) {
	_, stderr, err := runRedact(t, writeRedactConfig(t), 0, "run", "--redact")
	require.NoError(t, err)
	assert.Contains(t, stderr, "1 value(s) shorter than "+strconv.Itoa(logging.MinRedactedValueLen)+" bytes are not masked: PORT")
}

func TestRunRedact_MinLengthMasksShortValues(t *testing.T) {
	stdout, stderr, err := runRedact(t, writeRedactConfig(t), 0, "run", "--redact", "--redact-min-length", "2")
	require.NoError(t, err)
	assert.Contains(t, stdout, "port "+redact.Marker+" stays")
	assert.NotContains(t, stderr, "not masked")
}

func TestRunRedact_InvalidMinLength(t *testing.T) {
	chdirTmp(t, writeRedactConfig(t))
	_, _, err := runRootCmd(t, "run", "--redact", "--redact-min-length", "0", "--", os.Args[0])
	requireExit(t, err, skret.ExitValidationError)
	assert.Contains(t, err.Error(), "--redact-min-length")
}

func TestRunRedact_CommandNotFound(t *testing.T) {
	chdirTmp(t, writeRedactConfig(t))
	_, _, err := runRootCmd(t, "run", "--redact", "--", filepath.Join(t.TempDir(), "no-such-command"))
	requireExit(t, err, skret.ExitExecError)
	assert.Contains(t, err.Error(), "command not found")
}

func TestRunRedact_RejectsWatch(t *testing.T) {
	chdirTmp(t, writeRedactConfig(t))
	_, _, err := runRootCmd(t, "run", "--redact", "--watch", "--", os.Args[0])
	requireExit(t, err, skret.ExitValidationError)
	assert.Contains(t, err.Error(), "--watch")
}

func TestRunRedact_FlagDefaults(t *testing.T) {
	cmd := newRunCmd(&GlobalOpts{})
	redactFlag := cmd.Flags().Lookup("redact")
	require.NotNil(t, redactFlag)
	assert.Equal(t, "false", redactFlag.DefValue)
	minFlag := cmd.Flags().Lookup("redact-min-length")
	require.NotNil(t, minFlag)
	assert.Equal(t, strconv.Itoa(logging.MinRedactedValueLen), minFlag.DefValue, "the log redactor's minimum")
}

// Without --redact, run keeps handing the command skret's own stdio (process
// replacement on Unix), so the output reaches the caller unfiltered and the
// exit status is the command's own. The real process boundary matters here,
// so the test re-runs itself as a child that calls `skret run`.
func TestRun_WithoutRedactOutputIsUnfiltered(t *testing.T) {
	if dir := os.Getenv("SKRET_TEST_NOREDACT_DIR"); dir != "" {
		t.Setenv("SKRET_RUN_PRINT_FILE", filepath.Join(dir, "payload.txt"))
		t.Setenv("SKRET_RUN_PRINT_EXIT", "3")
		chdirTmp(t, dir)
		cmd := NewRootCmd()
		cmd.SetArgs([]string{"run", "--", os.Args[0]})
		// Only reached where run returns after the child exits (Windows).
		os.Exit(skret.ExitCode(cmd.Execute()))
	}

	dir := writeRedactConfig(t)
	child := osexec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestRun_WithoutRedactOutputIsUnfiltered$", "-test.count=1")
	child.Env = append(os.Environ(), "SKRET_TEST_NOREDACT_DIR="+dir)
	out, err := child.CombinedOutput()
	var exitErr *osexec.ExitError
	require.True(t, errors.As(err, &exitErr), "want the command's exit status, got %v", err)
	assert.Equal(t, 3, exitErr.ExitCode())
	assert.Contains(t, string(out), "token="+redactToken, "without --redact the output is not filtered")
	assert.NotContains(t, string(out), redact.Marker)
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("output closed") }

func TestRunRedact_ReportsUnflushableOutput(t *testing.T) {
	dir := writeRedactConfig(t)
	// No whitespace, so the redactor holds everything until the final flush.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "payload.txt"), []byte("no-trailing-newline"), 0o600))
	t.Setenv("SKRET_RUN_PRINT_FILE", filepath.Join(dir, "payload.txt"))
	chdirTmp(t, dir)

	cmd := NewRootCmd()
	cmd.SetOut(failingWriter{})
	cmd.SetErr(&strings.Builder{})
	cmd.SetArgs([]string{"run", "--redact", "--", os.Args[0]})
	err := cmd.Execute()
	requireExit(t, err, skret.ExitExecError)
	assert.Contains(t, err.Error(), "writing command output failed")
}

func TestRunRedact_StartFailureIsAnExecError(t *testing.T) {
	dir := writeRedactConfig(t)
	chdirTmp(t, dir)
	// An executable file that is not a program: found on lookup, fails to start.
	bogus := filepath.Join(t.TempDir(), "not-a-program")
	if runtime.GOOS == "windows" {
		bogus += ".exe"
	}
	require.NoError(t, os.WriteFile(bogus, []byte("\x00\x01 not an executable image"), 0o700))

	_, _, err := runRootCmd(t, "run", "--redact", "--", bogus)
	requireExit(t, err, skret.ExitExecError)
	assert.Contains(t, err.Error(), "runtime error")
}
