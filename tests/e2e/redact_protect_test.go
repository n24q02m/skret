package e2e_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Environment variables that switch the test binary into child mode when
// skret re-executes it as the `run --` command.
const (
	childModeEnv  = "SKRET_E2E_CHILD_MODE"
	childKeyEnv   = "SKRET_E2E_CHILD_KEY"
	childExitEnv  = "SKRET_E2E_CHILD_EXIT"
	redactKey     = "E2E_REDACT_TOKEN"
	redactValue   = "e2e-redact-value-4b7d1f" // fake, only meaningful to this test
	childModeLeak = "leak"
)

// childMain is the probe command: it "leaks" the secret named by
// SKRET_E2E_CHILD_KEY as-is on stdout and base64-encoded on stderr, split
// across two writes each, then exits with SKRET_E2E_CHILD_EXIT.
func childMain(mode string) int {
	if mode != childModeLeak {
		fmt.Fprintf(os.Stderr, "unknown child mode %q\n", mode)
		return 2
	}
	v := os.Getenv(os.Getenv(childKeyEnv))
	half := len(v) / 2
	fmt.Fprintf(os.Stdout, "token=%s", v[:half])
	fmt.Fprintf(os.Stdout, "%s done\n", v[half:])
	enc := base64.StdEncoding.EncodeToString([]byte(v))
	fmt.Fprintf(os.Stderr, "encoded %s", enc[:4])
	fmt.Fprintf(os.Stderr, "%s\n", enc[4:])
	code, _ := strconv.Atoi(os.Getenv(childExitEnv))
	return code
}

// initRedactRepo creates a local-provider project holding one secret.
func initRedactRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".git"), 0o755))
	secrets := fmt.Sprintf("version: \"1\"\nsecrets:\n  %s: %q\n", redactKey, redactValue)
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".secrets.dev.yaml"), []byte(secrets), 0o600))
	run(t, dir, "init", "--provider=local", "--file=./.secrets.dev.yaml")
	return dir
}

// runSplit runs the skret binary with stdout and stderr captured apart and
// returns them with the process exit code.
func runSplit(t *testing.T, dir string, env []string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), skretBinary, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err := cmd.Run()
	if err != nil {
		var exitErr *exec.ExitError
		require.True(t, errors.As(err, &exitErr), "skret %v did not run: %v", args, err)
		code = exitErr.ExitCode()
	}
	return out.String(), errOut.String(), code
}

func childEnv(exit int) []string {
	return []string{
		childModeEnv + "=" + childModeLeak,
		childKeyEnv + "=" + redactKey,
		childExitEnv + "=" + strconv.Itoa(exit),
	}
}

func TestE2E_RunRedact_MasksOutputAndKeepsExitCode(t *testing.T) {
	dir := initRedactRepo(t)
	child, err := os.Executable()
	require.NoError(t, err)
	encoded := base64.StdEncoding.EncodeToString([]byte(redactValue))

	for _, exit := range []int{0, 3} {
		t.Run(strconv.Itoa(exit), func(t *testing.T) {
			stdout, stderr, code := runSplit(t, dir, childEnv(exit), "run", "--redact", "--", child)
			assert.Equal(t, exit, code)
			assert.Equal(t, "token=[REDACTED] done\n", stdout)
			assert.Contains(t, stderr, "encoded [REDACTED]\n")
			assert.NotContains(t, stdout+stderr, redactValue)
			assert.NotContains(t, stdout+stderr, encoded)
			if exit != 0 {
				assert.Contains(t, stderr, "exit status 3")
			}
		})
	}
}

// Without --redact the child's output is passed through unmodified.
func TestE2E_Run_WithoutRedactIsUnchanged(t *testing.T) {
	dir := initRedactRepo(t)
	child, err := os.Executable()
	require.NoError(t, err)

	stdout, stderr, code := runSplit(t, dir, childEnv(0), "run", "--", child)
	assert.Equal(t, 0, code)
	assert.Equal(t, "token="+redactValue+" done\n", stdout)
	assert.Contains(t, stderr, base64.StdEncoding.EncodeToString([]byte(redactValue)))
}

func TestE2E_RunRedact_RejectsWatch(t *testing.T) {
	dir := initRedactRepo(t)
	_, _, code := runSplit(t, dir, nil, "run", "--redact", "--watch", "--", "unused")
	assert.Equal(t, 8, code)
}

type protectFinding struct {
	File string `json:"file"`
	Line int    `json:"line"`
	Rule string `json:"rule"`
}

// fakeGitHubToken is built at run time so no token-shaped literal is
// committed; it only has to match the github-pat shape.
func fakeGitHubToken() string {
	return "ghp_" + strings.Repeat("Z", 36)
}

func writeProtectFixtures(t *testing.T, dir string) {
	t.Helper()
	files := map[string]string{
		".env":         "DB_PASSWORD=not-a-real-password\n",
		".env.example": "DB_PASSWORD=\n",
		"settings.py":  "import os\n\nTOKEN = \"" + fakeGitHubToken() + "\"\n",
		"clean.txt":    "nothing to see here\n",
	}
	for name, body := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600))
	}
}

func TestE2E_Protect_Paths(t *testing.T) {
	dir := t.TempDir()
	writeProtectFixtures(t, dir)

	stdout, stderr, code := runSplit(t, dir, nil,
		"protect", "--format", "json", ".env", ".env.example", "settings.py", "clean.txt")
	assert.Equal(t, 10, code, "stderr: %s", stderr)
	var findings []protectFinding
	require.NoError(t, json.Unmarshal([]byte(stdout), &findings), stdout)
	assert.Equal(t, []protectFinding{
		{File: ".env", Line: 0, Rule: "env-file"},
		{File: "settings.py", Line: 3, Rule: "github-pat"},
	}, findings)
	assert.NotContains(t, stdout+stderr, fakeGitHubToken())
	assert.NotContains(t, stdout+stderr, "not-a-real-password")

	stdout, stderr, code = runSplit(t, dir, nil, "protect", "clean.txt", ".env.example")
	assert.Equal(t, 0, code)
	assert.Empty(t, stdout)
	assert.Contains(t, stderr, "No plaintext secrets found.")
}

// With no arguments, protect checks what is staged in the git index.
func TestE2E_Protect_Staged(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	dir := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), "git", args...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "git %v: %s", args, out)
	}
	git("init", "-q")
	writeProtectFixtures(t, dir)

	git("add", "clean.txt", ".env.example")
	_, stderr, code := runSplit(t, dir, nil, "protect")
	assert.Equal(t, 0, code, "stderr: %s", stderr)

	git("add", "settings.py")
	stdout, stderr, code := runSplit(t, dir, nil, "protect")
	assert.Equal(t, 10, code, "stderr: %s", stderr)
	assert.Contains(t, stdout, "settings.py")
	assert.Contains(t, stdout, "github-pat")
	assert.NotContains(t, stdout, "env-file", "an unstaged .env is not reported")
	assert.NotContains(t, stdout+stderr, fakeGitHubToken())
}
