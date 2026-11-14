package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	osexec "os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"

	"github.com/n24q02m/skret/internal/auth"
	"github.com/n24q02m/skret/internal/provider"
	"github.com/n24q02m/skret/pkg/skret"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// covDSSM is a fake AWS SSM endpoint (json 1.1 protocol). Operations listed
// in ok answer 200 with the given body; every other operation is rejected
// with a non-retryable AccessDeniedException, which the aws provider surfaces
// unchanged. It records each operation and the parameter name it targeted.
type covDSSM struct {
	mu    sync.Mutex
	ok    map[string]string
	ops   []string
	names []string
}

// covDAWSRepo starts the fake SSM endpoint, isolates the AWS SDK onto it and
// chdirs into a repo whose dev env is `provider: aws, path: /app/dev`.
func covDAWSRepo(t *testing.T, ok map[string]string) *covDSSM {
	t.Helper()
	s := &covDSSM{ok: ok}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		op := strings.TrimPrefix(r.Header.Get("X-Amz-Target"), "AmazonSSM.")
		body, _ := io.ReadAll(r.Body)
		var in struct{ Name string }
		_ = json.Unmarshal(body, &in)
		s.mu.Lock()
		s.ops = append(s.ops, op)
		s.names = append(s.names, in.Name)
		s.mu.Unlock()

		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		if resp, found := s.ok[op]; found {
			_, _ = w.Write([]byte(resp))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"__type":"AccessDeniedException","message":"covd denied ` + op + `"}`))
	}))
	t.Cleanup(srv.Close)
	covBIsolateAWS(t, "AWS_ENDPOINT_URL_SSM", srv.URL)
	covBAWSAuditRepo(t)
	return s
}

func (s *covDSSM) sawOp(op string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, o := range s.ops {
		if o == op {
			return true
		}
	}
	return false
}

func (s *covDSSM) targetedNames() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, n := range s.names {
		if n != "" {
			out = append(out, n)
		}
	}
	return out
}

// covDDeadURL returns the URL of an httptest server that is already closed,
// so any request to it fails locally with a connection error.
func covDDeadURL(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	u := srv.URL
	srv.Close()
	return u
}

// --- provider read/write failures surface as ExitProviderError ---

func TestCovDAWSProviderFailuresMapToProviderError(t *testing.T) {
	cases := []struct {
		name string
		args []string
		op   string
		want string
	}{
		{"list names", []string{"list"}, "GetParametersByPath", "list secrets failed"},
		{"list values", []string{"list", "--values"}, "GetParametersByPath", "list secrets failed"},
		{"scan", []string{"scan"}, "GetParametersByPath", "scan: list secrets failed"},
		{"env", []string{"env"}, "GetParametersByPath", "env: list secrets failed"},
		{"run", []string{"run", "--", "covd-never-launched"}, "GetParametersByPath", "run: list secrets failed"},
		{"get", []string{"get", "KEY"}, "GetParameter", `get "/app/dev/KEY" failed`},
		{"set", []string{"set", "KEY", "v"}, "GetParameter", `set "/app/dev/KEY"`},
		{"delete", []string{"delete", "KEY", "--force"}, "DeleteParameter", `delete "/app/dev/KEY" failed`},
		{"generate set", []string{"generate", "--set", "/app/dev/GEN"}, "GetParameter", `set "/app/dev/GEN"`},
		{"rotate read", []string{"rotate", "KEY", "--value", "x", "--yes"}, "GetParameter", `rotate "/app/dev/KEY": read current value`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := covDAWSRepo(t, nil)
			_, _, err := runRootCmd(t, tc.args...)
			requireExit(t, err, skret.ExitProviderError)
			assert.Contains(t, err.Error(), tc.want)
			assert.Contains(t, err.Error(), "covd denied", "the provider cause must be kept in the chain")
			assert.True(t, fake.sawOp(tc.op), "command must have reached SSM %s", tc.op)
		})
	}
}

func TestCovDTemplate_ProviderListFailure(t *testing.T) {
	fake := covDAWSRepo(t, nil)
	tmpl := filepath.Join(t.TempDir(), "app.tmpl")
	require.NoError(t, os.WriteFile(tmpl, []byte("url={{ .DB_URL }}\n"), 0o600))

	stdout, _, err := runRootCmd(t, "template", tmpl)
	requireExit(t, err, skret.ExitProviderError)
	assert.Contains(t, err.Error(), "template: list secrets failed")
	assert.Empty(t, stdout, "a failed template must not render anything")
	assert.True(t, fake.sawOp("GetParametersByPath"))
}

func TestCovDBrowse_ProviderListFailure(t *testing.T) {
	orig := isTerminal
	isTerminal = func() bool { return true }
	t.Cleanup(func() { isTerminal = orig })
	fake := covDAWSRepo(t, nil)

	_, _, err := runRootCmd(t, "browse")
	requireExit(t, err, skret.ExitProviderError)
	assert.Contains(t, err.Error(), "browse: list secrets failed")
	assert.True(t, fake.sawOp("GetParametersByPath"))
}

func TestCovDDiff_EnvSideFailureStopsBeforeGitHub(t *testing.T) {
	fake := covDAWSRepo(t, nil)
	t.Setenv("GITHUB_TOKEN", "covd-not-a-real-token")

	stdout, _, err := runRootCmd(t, "diff", "dev", "--to=github", "--github-repo", "o/r")
	requireExit(t, err, skret.ExitProviderError)
	assert.Contains(t, err.Error(), "diff failed")
	assert.Empty(t, stdout)
	assert.True(t, fake.sawOp("GetParametersByPath"), "the env side is read first")
}

func TestCovDRotate_WriteFailureAfterSuccessfulRead(t *testing.T) {
	fake := covDAWSRepo(t, map[string]string{
		"GetParameter": `{"Parameter":{"Name":"/app/dev/KEY","Value":"old","Version":4}}`,
	})

	_, _, err := runRootCmd(t, "rotate", "KEY", "--value", "new-value", "--yes")
	requireExit(t, err, skret.ExitProviderError)
	assert.Contains(t, err.Error(), `rotate "/app/dev/KEY"`)
	assert.NotContains(t, err.Error(), "read current value", "the read succeeded; the write failed")
	assert.True(t, fake.sawOp("PutParameter"))
}

func TestCovDGet_ReferenceScopeListFailure(t *testing.T) {
	fake := covDAWSRepo(t, map[string]string{
		"GetParameter": `{"Parameter":{"Name":"/app/dev/KEY","Value":"prefix-${OTHER}","Version":1}}`,
	})

	stdout, _, err := runRootCmd(t, "get", "KEY")
	requireExit(t, err, skret.ExitProviderError)
	assert.Contains(t, err.Error(), "get: list scope for reference resolution failed")
	assert.NotContains(t, stdout, "prefix-", "an unresolved reference value must not be printed")
	assert.True(t, fake.sawOp("GetParametersByPath"))
}

func TestCovDList_NonRecursiveKeepsOnlyDirectChildren(t *testing.T) {
	covDAWSRepo(t, map[string]string{
		"GetParametersByPath": `{"Parameters":[{"Name":"/app/dev/A","Version":1},{"Name":"/app/dev/sub/B","Version":1}]}`,
	})

	stdout, _, err := runRootCmd(t, "list", "--recursive=false", "--format", "json")
	require.NoError(t, err)
	var items []map[string]any
	require.NoError(t, json.Unmarshal([]byte(stdout), &items), stdout)
	require.Len(t, items, 1, "the nested key must be filtered out: %s", stdout)
	assert.Contains(t, items[0]["key"], "A")
	assert.NotContains(t, stdout, "sub/B")
}

func TestCovDCompletion_ListFailureYieldsNoCandidates(t *testing.T) {
	fake := covDAWSRepo(t, nil)

	names, directive := secretKeyCompletion(&GlobalOpts{})(&cobra.Command{}, nil, "")
	assert.Empty(t, names)
	assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive)
	assert.True(t, fake.sawOp("GetParametersByPath"), "completion must have tried to list names")
}

// --- shell-mangled key arguments are repaired before reaching the provider ---

func TestCovDKeyCommands_RepairShellMangledKey(t *testing.T) {
	t.Setenv("SKRET_EXPERIMENTAL", "1")
	const mangled = "C:/Program Files/Git/app/dev/KEY"
	cases := []struct {
		name string
		args []string
	}{
		{"get", []string{"get", mangled}},
		{"set", []string{"set", mangled, "v9"}},
		{"delete", []string{"delete", mangled, "--force"}},
		{"history", []string{"history", mangled}},
		{"rollback", []string{"rollback", mangled, "1", "--force"}},
		{"rotate", []string{"rotate", mangled, "--value", "rotated", "--yes"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := covDAWSRepo(t, map[string]string{
				"GetParameter":        `{"Parameter":{"Name":"/app/dev/KEY","Value":"v2","Version":2}}`,
				"PutParameter":        `{"Version":3}`,
				"DeleteParameter":     `{}`,
				"GetParameterHistory": `{"Parameters":[{"Name":"/app/dev/KEY","Value":"v1","Version":1},{"Name":"/app/dev/KEY","Value":"v2","Version":2}]}`,
			})
			_, stderr, err := runRootCmd(t, tc.args...)
			require.NoError(t, err, stderr)
			assert.Contains(t, stderr, `warning: key looked shell-mangled; using "/app/dev/KEY"`)
			names := fake.targetedNames()
			require.NotEmpty(t, names)
			for _, n := range names {
				assert.Equal(t, "/app/dev/KEY", n, "the provider must only see the repaired key")
			}
		})
	}
}

func TestCovDHistoryAndRollback_Render(t *testing.T) {
	t.Setenv("SKRET_EXPERIMENTAL", "1")
	covDAWSRepo(t, map[string]string{
		"GetParameter":        `{"Parameter":{"Name":"/app/dev/KEY","Value":"second-value","Version":2}}`,
		"PutParameter":        `{"Version":3}`,
		"GetParameterHistory": `{"Parameters":[{"Name":"/app/dev/KEY","Value":"first-value","Version":1},{"Name":"/app/dev/KEY","Value":"second-value","Version":2}]}`,
	})

	stdout, _, err := runRootCmd(t, "history", "KEY")
	require.NoError(t, err)
	assert.Contains(t, stdout, "VERSION")
	assert.NotContains(t, stdout, "first-value", "history masks values without --verbose")

	_, stderr, err := runRootCmd(t, "rollback", "KEY", "1", "--force")
	require.NoError(t, err)
	assert.Contains(t, stderr, `Successfully rolled back "/app/dev/KEY" to version 1`)

	_, _, err = runRootCmd(t, "rollback", "KEY", "7", "--force")
	requireExit(t, err, skret.ExitNotFoundError)
	assert.Contains(t, err.Error(), `"/app/dev/KEY" has no version 7`)
}

// --- config resolution failures stop before any provider is built ---

func TestCovDMissingExplicitConfigIsConfigError(t *testing.T) {
	t.Setenv("SKRET_EXPERIMENTAL", "1")
	orig := isTerminal
	isTerminal = func() bool { return true }
	t.Cleanup(func() { isTerminal = orig })
	chdirTmp(t, t.TempDir())
	missing := filepath.Join(t.TempDir(), "missing.yaml")

	cases := [][]string{
		{"get", "K"},
		{"set", "K", "v"},
		{"delete", "K", "--force"},
		{"history", "K"},
		{"rollback", "K", "1", "--force"},
		{"rotate", "K", "--value", "x", "--yes"},
		{"run", "--", "covd-never-launched"},
		{"browse"},
	}
	for _, args := range cases {
		t.Run(args[0], func(t *testing.T) {
			_, _, err := runRootCmd(t, append([]string{"--config", missing}, args...)...)
			requireExit(t, err, skret.ExitConfigError)
			assert.Contains(t, err.Error(), "load config failed")
			assert.Contains(t, err.Error(), "missing.yaml")
		})
	}
}

func TestCovDLoadProvider_CorruptLocalStoreIsProviderError(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "dev.yaml"), []byte("secrets: [unterminated\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".skret.yaml"),
		[]byte("version: \"1\"\ndefault_env: dev\nenvironments:\n  dev:\n    provider: local\n    file: dev.yaml\n"), 0o600))
	chdirTmp(t, dir)

	_, _, err := runRootCmd(t, "get", "K")
	requireExit(t, err, skret.ExitProviderError)
	assert.Contains(t, err.Error(), `init provider "local" failed`)
}

func TestCovDDiff_ArgumentValidation(t *testing.T) {
	chdirTmp(t, writeLocalTemplateConfig(t))
	cases := []struct {
		name string
		args []string
		code int
		want string
	}{
		{"dotenv with two envs", []string{"dev", "dev", "--dotenv", "x.env"}, skret.ExitValidationError, "--dotenv takes exactly one positional"},
		{"github with two envs", []string{"dev", "dev", "--to=github"}, skret.ExitValidationError, "--to=github takes exactly one positional"},
		{"unknown target", []string{"dev", "--to=bogus"}, skret.ExitValidationError, `unknown --to "bogus"`},
		{"no second side", []string{"dev"}, skret.ExitValidationError, "diff needs a second env, --dotenv, or --to=github"},
		{"unknown first env", []string{"covd-no-such-env", "--dotenv", "x.env"}, skret.ExitConfigError, "resolve config failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stdout, _, err := runRootCmd(t, append([]string{"diff"}, tc.args...)...)
			requireExit(t, err, tc.code)
			assert.Contains(t, err.Error(), tc.want)
			assert.Empty(t, stdout)
		})
	}
}

// --- ttl parsing ---

func TestCovDParseTTL_RejectsNonPositiveDays(t *testing.T) {
	for _, in := range []string{"0d", "-3d"} {
		_, err := parseTTL(in)
		require.Error(t, err, in)
		assert.Contains(t, err.Error(), "must be positive (got "+in+")")
	}
	d, err := parseTTL("2d")
	require.NoError(t, err)
	assert.Equal(t, 48*time.Hour, d)
}

func TestCovDSet_InvalidTTLLeavesStoreUntouched(t *testing.T) {
	dir := writeLocalTemplateConfig(t)
	chdirTmp(t, dir)
	before, err := os.ReadFile(filepath.Join(dir, "dev.yaml"))
	require.NoError(t, err)

	_, _, err = runRootCmd(t, "set", "NEW_KEY", "v", "--ttl", "bogus")
	requireExit(t, err, skret.ExitValidationError)
	assert.Contains(t, err.Error(), "set: --ttl invalid duration")
	after, err := os.ReadFile(filepath.Join(dir, "dev.yaml"))
	require.NoError(t, err)
	assert.Equal(t, string(before), string(after))
}

// --- auth login/logout/status ---

// covDAWSProfileHome points the home directory at a scratch dir that holds an
// ~/.aws/config declaring [profile covd]; the skret credential store lands
// in <home>/.skret/credentials.yaml.
func covDAWSProfileHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("SKRET_KEYRING", "")
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".aws"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(home, ".aws", "config"),
		[]byte("[profile covd]\nregion = eu-west-1\n"), 0o600))
	return home
}

func TestCovDAuthLogin_ProfileMethodStoresCredential(t *testing.T) {
	home := covDAWSProfileHome(t)

	_, stderr, err := runRootCmd(t, "auth", "login", "aws", "--method", "profile", "--opt", "profile=covd")
	require.NoError(t, err)
	assert.Contains(t, stderr, "Successfully authenticated with aws")

	cred, err := auth.NewStoreWithPath(filepath.Join(home, ".skret", "credentials.yaml")).Load("aws")
	require.NoError(t, err)
	assert.Equal(t, "profile", cred.Method)
	assert.Equal(t, "covd", cred.Metadata["profile"])
}

func TestCovDAuthLogin_MalformedOptRejected(t *testing.T) {
	home := covDAWSProfileHome(t)

	_, _, err := runRootCmd(t, "auth", "login", "aws", "--method", "profile", "--opt", "profile")
	requireExit(t, err, skret.ExitConfigError)
	assert.Contains(t, err.Error(), `--opt must be key=value, got "profile"`)
	_, statErr := os.Stat(filepath.Join(home, ".skret", "credentials.yaml"))
	assert.True(t, os.IsNotExist(statErr), "a rejected login must not write the store")
}

func TestCovDAuthLogout_UnreadableStoreFails(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("SKRET_KEYRING", "")
	store := filepath.Join(home, ".skret", "credentials.yaml")
	require.NoError(t, os.MkdirAll(filepath.Dir(store), 0o700))
	require.NoError(t, os.WriteFile(store, []byte("providers: [unterminated\n"), 0o600))

	_, stderr, err := runRootCmd(t, "auth", "logout", "doppler")
	requireExit(t, err, skret.ExitGenericError)
	assert.Contains(t, err.Error(), "auth logout doppler failed")
	assert.NotContains(t, stderr, "Logged out")
}

func TestCovDGetCredentialStatus_UnresolvableIsInvalid(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("SKRET_KEYRING", "")

	// The credential passed in is not expired, but nothing is stored for
	// doppler, so resolution fails and the status must not read "valid".
	assert.Equal(t, "invalid", getCredentialStatus(context.Background(), "doppler", &auth.Credential{Method: "token"}))
}

func TestCovDSetupAuthHook_DefaultCopiesOptsAndLogsIn(t *testing.T) {
	home := covDAWSProfileHome(t)
	opts := map[string]string{"profile": "covd"}

	require.NoError(t, setupAuthHook("aws", "profile", opts))
	assert.Equal(t, map[string]string{"profile": "covd"}, opts, "the caller's opts must not gain a method key")

	cred, err := auth.NewStoreWithPath(filepath.Join(home, ".skret", "credentials.yaml")).Load("aws")
	require.NoError(t, err)
	assert.Equal(t, "profile", cred.Method)
	assert.Equal(t, "covd", cred.Metadata["profile"])
}

// --- list rendering ---

func TestCovDPrintSecrets_EmptyTableAndJSON(t *testing.T) {
	var out, errOut bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)

	require.NoError(t, printSecrets(cmd, nil, "table", true))
	assert.Empty(t, out.String(), "an empty table prints no header")
	assert.Contains(t, errOut.String(), "No secrets found")

	out.Reset()
	errOut.Reset()
	require.NoError(t, printSecrets(cmd, nil, "json", true))
	var items []map[string]any
	require.NoError(t, json.Unmarshal(out.Bytes(), &items))
	assert.Empty(t, items, "json output stays a valid empty array")
	assert.Contains(t, errOut.String(), "No secrets found")
}

func TestCovDWarnNearExpiry_ExpiredSecret(t *testing.T) {
	var errOut bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetErr(&errOut)

	warnNearExpiry(cmd, []*provider.Secret{
		{Key: "OLD_TOKEN", Meta: provider.SecretMeta{ExpiresAt: time.Now().Add(-2 * time.Hour)}},
		{Key: "NO_EXPIRY"},
	})
	assert.Contains(t, errOut.String(), "warning: OLD_TOKEN expired ")
	assert.Contains(t, errOut.String(), "skret rotate OLD_TOKEN --ttl <duration>")
	assert.NotContains(t, errOut.String(), "NO_EXPIRY")
}

// --- scan ---

func TestCovDScan_MaxCountRequiresHistory(t *testing.T) {
	chdirTmp(t, writeLocalTemplateConfig(t))

	_, _, err := runScan(t, "--max-count", "5")
	requireExit(t, err, skret.ExitGenericError)
	assert.Contains(t, err.Error(), "--max-count only applies to --history")
}

func TestCovDScan_StagedLeakReportsStagedScope(t *testing.T) {
	dir := initHistoryRepo(t)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "leak.txt"), []byte("token=tok123\n"), 0o600))
	runGitCLI(t, dir, "add", "leak.txt")

	stdout, _, err := runScan(t, "--staged")
	requireExit(t, err, skret.ExitLeakFound)
	assert.Contains(t, err.Error(), "found in staged files")
	assert.Contains(t, stdout, "leak.txt")
	assert.Contains(t, stdout, "TOKEN")
	assert.NotContains(t, stdout, "tok123", "scan output must never echo the secret value")
}

// --- env-name collisions ---

func TestCovDEnvNameCollision_RunAndEnvRefuse(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "dev.yaml"),
		[]byte("version: \"1\"\nsecrets:\n  db-url: one\n  DB_URL: two\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".skret.yaml"),
		[]byte("version: \"1\"\ndefault_env: dev\nenvironments:\n  dev:\n    provider: local\n    file: dev.yaml\n"), 0o600))
	chdirTmp(t, dir)

	for _, args := range [][]string{{"run", "--", "covd-never-launched"}, {"env"}} {
		stdout, _, err := runRootCmd(t, args...)
		requireExit(t, err, skret.ExitConfigError)
		assert.Contains(t, err.Error(), args[0]+`: env var name "DB_URL" is produced by two distinct keys`)
		assert.Empty(t, stdout, "%s must not emit a partial env", args[0])
	}
}

func TestCovDValidateRequired_PresentSecretPasses(t *testing.T) {
	secrets := []*provider.Secret{{Key: "/app/dev/API_KEY", Value: "x"}}
	require.NoError(t, validateRequired(secrets, []string{"API_KEY"}, "/app/dev"))

	t.Setenv("COVD_ONLY_IN_ENV", "")
	err := validateRequired(secrets, []string{"API_KEY", "COVD_ONLY_IN_ENV"}, "/app/dev")
	requireExit(t, err, skret.ExitValidationError)
	assert.Contains(t, err.Error(), `required secret "COVD_ONLY_IN_ENV" not found`)
}

func TestCovDExecCommand_SuccessfulChildReturnsNil(t *testing.T) {
	env := append(os.Environ(), "SKRET_RUN_CHILD=0")
	if runtime.GOOS == "windows" {
		// Windows runs the command as a subprocess and returns its outcome.
		require.NoError(t, execCommand([]string{os.Args[0]}, env))
		return
	}
	// On Unix execCommand replaces the process image, so drive it from a
	// re-executed copy of this test binary and assert that copy exits 0.
	if os.Getenv("COVD_EXEC_CHILD") == "1" {
		err := execCommand([]string{os.Args[0]}, env)
		t.Fatalf("execCommand returned instead of replacing the process: %v", err)
	}
	child := osexec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestCovDExecCommand_SuccessfulChildReturnsNil$", "-test.count=1")
	child.Env = append(os.Environ(), "COVD_EXEC_CHILD=1")
	out, err := child.CombinedOutput()
	require.NoError(t, err, "exec'd child must exit 0: %s", out)
	assert.NotContains(t, string(out), "returned instead of replacing")
}

// --- randomness failures ---

func covDFailingRand(t *testing.T) {
	t.Helper()
	orig := genRandReader
	genRandReader = iotest.ErrReader(errors.New("covd entropy exhausted"))
	t.Cleanup(func() { genRandReader = orig })
}

func TestCovDGenerate_RandFailure(t *testing.T) {
	covDFailingRand(t)
	chdirTmp(t, t.TempDir())

	stdout, _, err := runRootCmd(t, "generate")
	requireExit(t, err, skret.ExitGenericError)
	assert.Contains(t, err.Error(), "generate: crypto/rand failed")
	assert.Empty(t, stdout)
}

func TestCovDRotate_RandFailureKeepsOldValue(t *testing.T) {
	dir := rotateSetupRepo(t)
	covDFailingRand(t)

	_, _, err := runRotate(t, dir, "API_KEY", "--yes")
	requireExit(t, err, skret.ExitGenericError)
	assert.Contains(t, err.Error(), "rotate: crypto/rand failed")
	assert.Equal(t, "secret123", readRotateStore(t, dir).Secrets["API_KEY"])
}

// --- notify / sync side effects of rotate and delete ---

func TestCovDStrictNotify_RotateAndDeleteFailOnDeadWebhook(t *testing.T) {
	dir := rotateSetupRepoWithConfig(t, "version: \"1\"\ndefault_env: dev\nenvironments:\n  dev:\n    provider: local\n    file: ./.secrets.dev.yaml\nnotify:\n  webhook_url: "+covDDeadURL(t)+"\n")

	_, _, err := runRotate(t, dir, "API_KEY", "--value", "rotated-value", "--yes", "--strict-notify", "--no-sync")
	requireExit(t, err, skret.ExitNetworkError)
	assert.Contains(t, err.Error(), "notify webhook failed (the mutation itself succeeded)")
	assert.Equal(t, "rotated-value", readRotateStore(t, dir).Secrets["API_KEY"], "the rotation is durable even when notify fails")

	_, _, err = runRootCmd(t, "delete", "DB_PASS", "--force", "--strict-notify")
	requireExit(t, err, skret.ExitNetworkError)
	assert.Contains(t, err.Error(), "notify webhook failed")
	_, still := readRotateStore(t, dir).Secrets["DB_PASS"]
	assert.False(t, still, "the delete is durable even when notify fails")
}

func TestCovDRotate_TargetSyncFailureIsOnlyAWarning(t *testing.T) {
	dir := rotateSetupRepoWithConfig(t, fmt.Sprintf("version: \"1\"\ndefault_env: dev\nenvironments:\n  dev:\n    provider: local\n    file: ./.secrets.dev.yaml\nsync:\n  targets:\n    - type: github\n      repo: o/r\n      base_url: %s\n", covDDeadURL(t)))
	t.Setenv("GITHUB_TOKEN", "")

	_, stderr, err := runRotate(t, dir, "API_KEY", "--value", "rotated-value", "--yes")
	require.NoError(t, err, "a target failure must not fail a durable rotation")
	assert.Contains(t, stderr, "warning: rotate: target sync failed")
	assert.Equal(t, "rotated-value", readRotateStore(t, dir).Secrets["API_KEY"])
}

// --- pure helpers ---

func TestCovDResolveValue_ChainDeeperThanMaxDepth(t *testing.T) {
	values := map[string]string{}
	for i := range 12 {
		values[fmt.Sprintf("K%d", i)] = fmt.Sprintf("${K%d}", i+1)
	}
	values["K12"] = "literal"
	lookup := func(name string) (string, bool) {
		v, ok := values[name]
		return v, ok
	}

	_, err := resolveValue("${K0}", "OWNER", lookup)
	requireExit(t, err, skret.ExitValidationError)
	assert.Contains(t, err.Error(), "OWNER: reference chain deeper than 10 hops")
	assert.Contains(t, skret.RemediationOf(err), "no value sits more than 10 references deep")
}

func TestCovDWrapProviderMutationError_UnknownOutcome(t *testing.T) {
	partial := &provider.PartialCommitError{
		Provider:        "aws",
		Key:             "/app/dev/KEY",
		PreVersion:      4,
		CommitState:     provider.MutationCommitUnknown,
		ObservedVersion: 5,
		TagState:        "unverified",
	}
	err := wrapProviderMutationError("set", "/app/dev/KEY", fmt.Errorf("wrapped: %w", partial))
	requireExit(t, err, skret.ExitProviderError)
	assert.Contains(t, err.Error(),
		`set "/app/dev/KEY" mutation outcome unknown; reconcile before retry (pre-version 4, observed version 5, tag state unverified)`)
	var got *provider.PartialCommitError
	require.ErrorAs(t, err, &got)
	assert.Same(t, partial, got)
}

func TestCovDLLMsCommandRows_SkipsHiddenSubtree(t *testing.T) {
	root := &cobra.Command{Use: "covd", Short: "root"}
	visible := &cobra.Command{Use: "shown", Short: "visible", Run: func(*cobra.Command, []string) {}}
	hidden := &cobra.Command{Use: "secret-cmd", Short: "hidden", Hidden: true, Run: func(*cobra.Command, []string) {}}
	hidden.AddCommand(&cobra.Command{Use: "below", Short: "under hidden", Run: func(*cobra.Command, []string) {}})
	root.AddCommand(visible, hidden)

	var cmds []string
	for _, r := range llmsCommandRows(root) {
		cmds = append(cmds, r.Command)
	}
	assert.Contains(t, cmds, "covd shown")
	for _, c := range cmds {
		assert.NotContains(t, c, "secret-cmd", "hidden commands and their children are not advertised")
	}
}

func TestCovDRenderLLMsText_ProviderWithoutDisplayName(t *testing.T) {
	_, known := providerDisplayNames["covd-unlisted"]
	require.False(t, known)
	var buf bytes.Buffer
	require.NoError(t, renderLLMsText(&buf, llmsManifest{Version: "9.9.9", Providers: []string{"covd-unlisted"}}))
	assert.Contains(t, buf.String(), "## Providers (1)\n\n- covd-unlisted\n")
}
