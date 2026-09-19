package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/n24q02m/skret/internal/auth"
	"github.com/n24q02m/skret/internal/keystore"
	"github.com/n24q02m/skret/pkg/skret"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// doctorFixture writes a repo with the given .skret.yaml body plus an
// optional secrets file for local providers, then chdirs into it.
func doctorFixture(t *testing.T, configYAML string, secretsFiles map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".git"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".skret.yaml"), []byte(configYAML), 0o644))
	for name, body := range secretsFiles {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600))
	}
	orig, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { _ = os.Chdir(orig) })
	return dir
}

const doctorLocalConfig = `version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: ./.secrets.dev.yaml
`

const doctorSecretsFile = `version: "1"
secrets:
  DATABASE_URL: "postgres://dev:dev@localhost/db"
  API_KEY: "secret123"
`

// runDoctorCmd executes `skret doctor [extraArgs...]` with isolated stdout
// and stderr buffers and a scratch credential store, returning the buffers
// and the RunE error.
func runDoctorCmd(t *testing.T, extraArgs ...string) (stdout, stderr string, err error) {
	t.Helper()
	// Never read (or worse, write) the operator's real credential store.
	scratch := auth.NewStoreWithPath(filepath.Join(t.TempDir(), "credentials.yaml"))
	origStore := doctorStoreFactory
	doctorStoreFactory = func() *auth.Store { return scratch }
	t.Cleanup(func() { doctorStoreFactory = origStore })

	var outBuf, errBuf strings.Builder
	cmd := NewRootCmd()
	cmd.SetOut(&outBuf)
	cmd.SetErr(&errBuf)
	cmd.SetArgs(append([]string{"doctor"}, extraArgs...))
	err = cmd.Execute()
	return outBuf.String(), errBuf.String(), err
}

func TestDoctorCmd_HealthyLocalAllPass(t *testing.T) {
	doctorFixture(t, doctorLocalConfig, map[string]string{".secrets.dev.yaml": doctorSecretsFile})

	stdout, stderr, err := runDoctorCmd(t)
	require.NoError(t, err)

	// Summary (data) on stdout; per-check status lines on stderr.
	// provider pass + permissions pass + encryption warn.
	assert.Equal(t, "doctor: 2 passed, 1 warning(s), 0 failed\n", stdout)
	assert.Contains(t, stderr, "PASS provider[dev]: file loads (2 secret(s))")
	assert.Contains(t, stderr, "PASS permissions[dev]")
	assert.Contains(t, stderr, "WARN encryption[dev]: plaintext (default for dev;")
	// Windows/perms branch differs by platform; both must be a PASS line.
	assert.NotContains(t, stderr, "FAIL")
}

func TestDoctorCmd_TableFormatShowsRemediationHint(t *testing.T) {
	doctorFixture(t, doctorLocalConfig, nil) // no secrets file

	_, stderr, err := runDoctorCmd(t)
	require.NoError(t, err)

	assert.Contains(t, stderr, "WARN provider[dev]: no secrets file yet")
	assert.Contains(t, stderr, "fix: run 'skret set <KEY>' to create it")
}

func TestDoctorCmd_JSONShape(t *testing.T) {
	doctorFixture(t, doctorLocalConfig, map[string]string{".secrets.dev.yaml": doctorSecretsFile})

	stdout, stderr, err := runDoctorCmd(t, "--format", "json")
	require.NoError(t, err)
	// Data on stdout only; stderr stays clean of the table lines.
	assert.Equal(t, "", stderr)

	var report struct {
		Checks []DoctorCheck `json:"checks"`
	}
	require.NoError(t, json.Unmarshal([]byte(stdout), &report))
	require.NotEmpty(t, report.Checks)

	byName := map[string]DoctorCheck{}
	for _, c := range report.Checks {
		byName[c.Name] = c
	}
	prov, ok := byName["provider[dev]"]
	require.True(t, ok, "missing provider[dev] check in %v", report.Checks)
	assert.Equal(t, "pass", prov.Status)
	assert.Contains(t, prov.Detail, "2 secret(s)")
	assert.Empty(t, prov.Remediation, "pass checks must not carry remediation")

	enc, ok := byName["encryption[dev]"]
	require.True(t, ok)
	assert.Equal(t, "warn", enc.Status)
	assert.NotEmpty(t, enc.Detail)

	// remediation is omitempty: the raw body of a pass check must not carry
	// the key at all.
	raw := map[string]any{}
	require.NoError(t, json.Unmarshal([]byte(stdout), &raw))
	checks := raw["checks"].([]any)
	for _, rawCheck := range checks {
		m := rawCheck.(map[string]any)
		if m["status"] == "pass" {
			assert.NotContains(t, m, "remediation")
		}
		assert.Contains(t, m, "name")
		assert.Contains(t, m, "detail")
	}
}

func TestDoctorCmd_ProviderUnreachableExitsNetworkClass(t *testing.T) {
	doctorFixture(t, `version: "1"
default_env: prod
environments:
  prod:
    provider: aws
    path: /myapp/prod
    region: us-east-1
`, nil)

	orig := doctorLivenessProbe
	doctorLivenessProbe = func(_ context.Context) error { return errors.New("dial tcp: connection refused") }
	t.Cleanup(func() { doctorLivenessProbe = orig })

	_, stderr, err := runDoctorCmd(t)
	require.Error(t, err)
	assert.Equal(t, skret.ExitNetworkError, skret.ExitCode(err))
	assert.Contains(t, stderr, "FAIL provider[prod]: unreachable: dial tcp: connection refused")
	assert.Contains(t, stderr, "fix: check network and region (AWS_REGION, or --region)")
}

func TestDoctorCmd_ProviderAuthRejectedExitsAuthClass(t *testing.T) {
	doctorFixture(t, `version: "1"
default_env: prod
environments:
  prod:
    provider: aws
    path: /myapp/prod
    region: us-east-1
`, nil)

	orig := doctorLivenessProbe
	doctorLivenessProbe = func(_ context.Context) error { return errors.New("credential not found: expired token") }
	t.Cleanup(func() { doctorLivenessProbe = orig })

	_, stderr, err := runDoctorCmd(t)
	require.Error(t, err)
	assert.Equal(t, skret.ExitAuthError, skret.ExitCode(err))
	assert.Contains(t, stderr, "FAIL provider[prod]")
	assert.Contains(t, stderr, "fix: run 'skret auth login aws'")
}

func TestDoctorCmd_AWSHealthyReportsAuthOnce(t *testing.T) {
	doctorFixture(t, `version: "1"
default_env: prod
environments:
  prod:
    provider: aws
    path: /myapp/prod
  prod2:
    provider: aws
    path: /myapp/prod2
`, nil)

	probes := 0
	orig := doctorLivenessProbe
	doctorLivenessProbe = func(_ context.Context) error { probes++; return nil }
	t.Cleanup(func() { doctorLivenessProbe = orig })

	stdout, stderr, err := runDoctorCmd(t)
	require.NoError(t, err)
	assert.Equal(t, 1, probes, "probe must run once per command, not per env")
	assert.Contains(t, stderr, "PASS provider[prod]: reachable")
	assert.Contains(t, stderr, "PASS provider[prod2]: reachable")
	assert.Contains(t, stderr, "WARN auth[aws]: no stored credential")
	assert.Contains(t, stdout, "doctor: 2 passed, 1 warning(s), 0 failed")
}

func TestDoctorCmd_BadConfigYAMLEnvelopeAndExit(t *testing.T) {
	doctorFixture(t, "version: [unclosed", nil)

	stdout, stderr, err := runDoctorCmd(t)
	require.Error(t, err)
	assert.Equal(t, skret.ExitConfigError, skret.ExitCode(err))
	assert.Contains(t, stderr, "FAIL config:")
	// The failing config is itself the reported check: the summary reflects
	// it on stdout.
	assert.Equal(t, "doctor: 0 passed, 0 warning(s), 1 failed\n", stdout)
}

func TestDoctorCmd_MissingConfigPointsAtSetup(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".git"), 0o755))
	orig, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { _ = os.Chdir(orig) })

	_, stderr, err := runDoctorCmd(t)
	require.Error(t, err)
	assert.Equal(t, skret.ExitConfigError, skret.ExitCode(err))
	assert.Contains(t, stderr, "FAIL config:")
	assert.Contains(t, stderr, "fix: "+configNotFoundMsg)
}

func TestDoctorCmd_UnknownEnvFilter(t *testing.T) {
	doctorFixture(t, doctorLocalConfig, map[string]string{".secrets.dev.yaml": doctorSecretsFile})

	_, stderr, err := runDoctorCmd(t, "--env", "staging")
	require.Error(t, err)
	assert.Equal(t, skret.ExitConfigError, skret.ExitCode(err))
	assert.Contains(t, stderr, `FAIL config: env "staging" not declared`)
	assert.Contains(t, stderr, "available: dev")
}

func TestDoctorCmd_EnvFilterLimitsChecks(t *testing.T) {
	doctorFixture(t, `version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: ./.secrets.dev.yaml
  prod:
    provider: aws
    path: /myapp/prod
`, map[string]string{".secrets.dev.yaml": doctorSecretsFile})

	probes := 0
	orig := doctorLivenessProbe
	doctorLivenessProbe = func(_ context.Context) error { probes++; return nil }
	t.Cleanup(func() { doctorLivenessProbe = orig })

	stdout, stderr, err := runDoctorCmd(t, "--env", "dev")
	require.NoError(t, err)
	assert.Equal(t, 0, probes, "--env dev must not probe aws")
	assert.Contains(t, stderr, "provider[dev]")
	assert.NotContains(t, stderr, "provider[prod]")
	assert.Contains(t, stdout, "doctor: 2 passed, 1 warning(s), 0 failed")
}

func TestDoctorCmd_PerEnvResolveFailureIsConfigClass(t *testing.T) {
	doctorFixture(t, `version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: ./.secrets.dev.yaml
  broken:
    provider: gcs
`, map[string]string{".secrets.dev.yaml": doctorSecretsFile})

	stdout, stderr, err := runDoctorCmd(t)
	require.Error(t, err)
	assert.Equal(t, skret.ExitConfigError, skret.ExitCode(err), "a broken second env must not block dev, but must fail the run")
	assert.Contains(t, stderr, "FAIL config[broken]")
	// The healthy environment still reports real results.
	assert.Contains(t, stderr, "PASS provider[dev]")
	assert.Contains(t, stdout, "1 failed")
}

func TestDoctorCmd_LocalCorruptSecretsFile(t *testing.T) {
	doctorFixture(t, doctorLocalConfig, map[string]string{".secrets.dev.yaml": "secrets: [unclosed"})

	_, stderr, err := runDoctorCmd(t)
	require.Error(t, err)
	assert.Equal(t, skret.ExitProviderError, skret.ExitCode(err))
	assert.Contains(t, stderr, "FAIL provider[dev]")
}

func TestDoctorAuthCheck_States(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "credentials.yaml")
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	deps := doctorDeps{
		liveness: func(_ context.Context) error { return nil },
		store:    auth.NewStoreWithPath(storePath),
		now:      func() time.Time { return now },
		goos:     "linux",
	}

	t.Run("missing-credential-is-warning", func(t *testing.T) {
		check := doctorAuthCheck(deps)
		assert.Equal(t, doctorWarn, check.Status)
		assert.Contains(t, check.Detail, "no stored credential")
		assert.Contains(t, check.Remediation, "skret auth login aws")
	})

	t.Run("expired-credential-fails", func(t *testing.T) {
		require.NoError(t, deps.store.Save(&auth.Credential{
			Provider: "aws", Method: "sso",
			ExpiresAt: now.Add(-time.Hour),
		}))
		check := doctorAuthCheck(deps)
		assert.Equal(t, doctorFail, check.Status)
		assert.Equal(t, skret.ExitAuthError, check.failClass)
		assert.Contains(t, check.Detail, "credential expired at")
	})

	t.Run("nearing-expiry-warns", func(t *testing.T) {
		require.NoError(t, deps.store.Save(&auth.Credential{
			Provider: "aws", Method: "sso",
			ExpiresAt: now.Add(2 * time.Hour),
		}))
		check := doctorAuthCheck(deps)
		assert.Equal(t, doctorWarn, check.Status)
		assert.Empty(t, check.failClass)
		assert.Contains(t, check.Detail, "credential expires in")
	})

	t.Run("healthy-credential-passes", func(t *testing.T) {
		require.NoError(t, deps.store.Save(&auth.Credential{
			Provider: "aws", Method: "sso",
			ExpiresAt: now.Add(48 * time.Hour),
		}))
		check := doctorAuthCheck(deps)
		assert.Equal(t, doctorPass, check.Status)
		assert.Contains(t, check.Detail, "valid (method: sso")
	})
}

func TestDoctorPermStatus_Table(t *testing.T) {
	tests := []struct {
		name    string
		goos    string
		perm    fs.FileMode
		want    string
		wantFix bool
	}{
		{"linux-tight", "linux", 0o600, doctorPass, false},
		{"linux-group-readable", "linux", 0o644, doctorWarn, true},
		{"linux-world-accessible", "linux", 0o777, doctorWarn, true},
		{"windows-never-fails", "windows", 0o666, doctorPass, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, detail, fix := doctorPermStatus(tt.goos, tt.perm)
			assert.Equal(t, tt.want, status)
			assert.NotEmpty(t, detail)
			if tt.wantFix {
				assert.NotEmpty(t, fix)
			} else {
				assert.Empty(t, fix)
			}
		})
	}
}

func TestDoctorEncryptionCheck_Table(t *testing.T) {
	passStatus := func() *keystore.Status {
		return &keystore.Status{Encrypted: true, Format: "age", KDF: "argon2id", KeyAvailable: true, KeySource: "env:SKRET_AGE_KEY"}
	}

	tests := []struct {
		name        string
		rawEnv      map[string]any
		status      *keystore.Status
		statusErr   error
		want        string
		wantClass   int
		wantRemed   string
		wantInDetal string
	}{
		{
			name:   "encrypted-with-key-passes",
			status: passStatus(),
			want:   doctorPass,
		},
		{
			name:        "encrypted-without-key-fails-auth-class",
			status:      &keystore.Status{Encrypted: true, Format: "age", KDF: "argon2id"},
			want:        doctorFail,
			wantClass:   skret.ExitAuthError,
			wantRemed:   "SKRET_AGE_KEY",
			wantInDetal: "no key material",
		},
		{
			name:   "plaintext-warns",
			status: &keystore.Status{Encrypted: false},
			want:   doctorWarn,
		},
		{
			name:        "plaintext-entropy-warnings-surface",
			status:      &keystore.Status{Warnings: []string{"API_TOKEN", "file holds high-entropy plaintext values"}},
			want:        doctorWarn,
			wantInDetal: "API_TOKEN",
		},
		{
			name:        "entropy-warnings-cap-at-three",
			status:      &keystore.Status{Warnings: []string{"K1", "K2", "K3", "K4", "summary"}},
			want:        doctorWarn,
			wantInDetal: "+2 more",
		},
		{
			name:        "encrypted-intent-plaintext-file-warns-pre-migration",
			rawEnv:      map[string]any{"encrypted": true},
			status:      &keystore.Status{Encrypted: false},
			want:        doctorWarn,
			wantRemed:   "skret keys init --encrypt-existing",
			wantInDetal: "pre-migration",
		},
		{
			name:      "status-error-warns-never-crashes",
			statusErr: errors.New("read: permission denied"),
			want:      doctorWarn,
		},
		{
			name:   "missing-config-flag-tolerated",
			rawEnv: nil,
			status: &keystore.Status{Encrypted: false},
			want:   doctorWarn,
		},
		{
			name:   "non-bool-flag-tolerated",
			rawEnv: map[string]any{"encrypted": "yes"},
			status: &keystore.Status{Encrypted: false},
			want:   doctorWarn,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deps := doctorDeps{
				statusOf: func(_ string, cfg bool) (*keystore.Status, error) {
					if tt.status != nil {
						tt.status.EncryptedCfg = cfg
					}
					return tt.status, tt.statusErr
				},
			}
			check := doctorEncryptionCheck(deps, "dev", "unused.yaml", tt.rawEnv)
			assert.Equal(t, tt.want, check.Status)
			assert.NotEmpty(t, check.Detail)
			if tt.wantClass != 0 {
				assert.Equal(t, tt.wantClass, check.failClass)
			} else {
				assert.Zero(t, check.failClass)
			}
			if tt.wantRemed != "" {
				assert.Contains(t, check.Remediation, tt.wantRemed)
			}
			if tt.wantInDetal != "" {
				assert.Contains(t, check.Detail, tt.wantInDetal)
			}
		})
	}
}

func TestDoctorCmd_EncryptedFileWithKeyPasses(t *testing.T) {
	// Real keystore round-trip: env-var key material deterministically wins
	// over any machine keyring (SKRET_AGE_KEY is first in the resolve order).
	material, err := keystore.GenerateKey()
	require.NoError(t, err)
	t.Setenv("SKRET_AGE_KEY", material)

	sealed, err := keystore.Seal(map[string]string{"API_KEY": "v"}, material, nil)
	require.NoError(t, err)
	doctorFixture(t, `version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: ./.secrets.dev.yaml
    encrypted: true
`, map[string]string{".secrets.dev.yaml": string(sealed)})

	_, stderr, err := runDoctorCmd(t)
	require.NoError(t, err)
	assert.Contains(t, stderr, "PASS encryption[dev]: encrypted (format skret-encrypted-v1, kdf argon2id, key from env:SKRET_AGE_KEY)")
	assert.Contains(t, stderr, "PASS provider[dev]: file loads (1 secret(s))")
}

func TestDoctorCmd_EncryptedFileWithoutKeyFailsAuthClass(t *testing.T) {
	// Plain-looking file so provider[dev] loads without touching any key
	// material; the faked status seam then reports an on-disk envelope with
	// no available key — the exact branch doctor must surface as auth-class.
	doctorFixture(t, `version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: ./.secrets.dev.yaml
`, map[string]string{".secrets.dev.yaml": doctorSecretsFile})

	orig := doctorStatusOf
	doctorStatusOf = func(_ string, cfg bool) (*keystore.Status, error) {
		return &keystore.Status{Encrypted: true, Format: keystore.Format, KDF: "argon2id", EncryptedCfg: cfg}, nil
	}
	t.Cleanup(func() { doctorStatusOf = orig })

	_, stderr, err := runDoctorCmd(t)
	require.Error(t, err)
	assert.Equal(t, skret.ExitAuthError, skret.ExitCode(err))
	assert.Contains(t, stderr, "FAIL encryption[dev]")
	assert.Contains(t, stderr, "fix: export SKRET_AGE_KEY=")
}

func TestDoctorLocalFailureClassification(t *testing.T) {
	assert.Equal(t, skret.ExitProviderError, doctorLocalFailureClass(errors.New("yaml: unmarshal errors")))
	assert.Contains(t, doctorLocalFailureRemediation(errors.New("yaml: boom")), "corrupt YAML")

	// A failure that already carries a class + remediation keeps both
	// (keystore auth errors travel through skret.ExitCode/RemediationOf).
	carried := skret.NewError(skret.ExitAuthError, "keys: no key material", nil)
	assert.Equal(t, skret.ExitAuthError, doctorLocalFailureClass(carried))
	assert.Contains(t, doctorLocalFailureRemediation(carried), "corrupt YAML", "carried class keeps the fallback hint when no remediation attached")

	carriedWithHint := skret.WithRemediation(carried, "set SKRET_AGE_KEY")
	assert.Contains(t, doctorLocalFailureRemediation(carriedWithHint), "SKRET_AGE_KEY")
}

func TestDoctorFailure_ClassPrecedence(t *testing.T) {
	configFail := DoctorCheck{Status: doctorFail, failClass: skret.ExitConfigError, Name: "config"}
	providerFail := DoctorCheck{Status: doctorFail, failClass: skret.ExitProviderError, Name: "provider[x]"}
	authFail := DoctorCheck{Status: doctorFail, failClass: skret.ExitAuthError, Name: "auth[aws]"}
	networkFail := DoctorCheck{Status: doctorFail, failClass: skret.ExitNetworkError, Name: "provider[y]"}
	warnOnly := DoctorCheck{Status: doctorWarn, Name: "encryption[x]"}

	tests := []struct {
		name     string
		checks   []DoctorCheck
		wantCode int
		wantFail bool
	}{
		{"all-clean", []DoctorCheck{warnOnly}, skret.ExitSuccess, false},
		{"config-wins", []DoctorCheck{networkFail, authFail, providerFail, configFail}, skret.ExitConfigError, true},
		{"provider-over-auth", []DoctorCheck{networkFail, authFail, providerFail}, skret.ExitProviderError, true},
		{"auth-over-network", []DoctorCheck{networkFail, authFail}, skret.ExitAuthError, true},
		{"network-only", []DoctorCheck{networkFail}, skret.ExitNetworkError, true},
		{"unclassified-fail-closed", []DoctorCheck{{Status: doctorFail, Name: "mystery"}}, skret.ExitGenericError, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, failed, names := doctorFailure(tt.checks)
			assert.Equal(t, tt.wantCode, code)
			assert.Equal(t, tt.wantFail, failed)
			if tt.wantFail {
				assert.NotEmpty(t, names)
			}
		})
	}
}

func TestDoctorCmd_ExitZeroOnWarningsOnly(t *testing.T) {
	doctorFixture(t, doctorLocalConfig, map[string]string{".secrets.dev.yaml": doctorSecretsFile})

	_, _, err := runDoctorCmd(t)
	require.NoError(t, err, "warnings (plaintext default, missing probe) must not fail doctor")
}

func TestDoctorCmd_ProbeTimeoutFlagRespected(t *testing.T) {
	doctorFixture(t, `version: "1"
default_env: prod
environments:
  prod:
    provider: aws
    path: /myapp/prod
`, nil)

	var gotTimeout time.Duration
	orig := doctorLivenessProbe
	doctorLivenessProbe = func(ctx context.Context) error {
		deadline, ok := ctx.Deadline()
		if !ok {
			return errors.New("no deadline set")
		}
		gotTimeout = time.Until(deadline)
		return nil
	}
	t.Cleanup(func() { doctorLivenessProbe = orig })

	_, _, err := runDoctorCmd(t, "--timeout", "3s")
	require.NoError(t, err)
	assert.Greater(t, gotTimeout, 2*time.Second, "probe ctx must carry the --timeout deadline")
	assert.LessOrEqual(t, gotTimeout, 3*time.Second)
}

func TestDoctorCmd_ErrorsUseJSONEnvelope(t *testing.T) {
	doctorFixture(t, "version: [unclosed", nil)

	_, _, err := runDoctorCmd(t, "--format", "json")
	require.Error(t, err)

	// main() renders the failing command's error via RenderError in the
	// requested format; assert the real envelope contract end to end.
	var buf strings.Builder
	RenderError(&buf, err, "json")
	var env struct {
		Error       string `json:"error"`
		Code        int    `json:"code"`
		Remediation string `json:"remediation"`
	}
	require.NoError(t, json.Unmarshal([]byte(buf.String()), &env))
	assert.Equal(t, skret.ExitConfigError, env.Code)
	assert.Contains(t, env.Error, "doctor:")
	assert.NotEmpty(t, env.Remediation, "doctor envelope must carry the first failing check's fix hint")
}

func TestDoctorRegisteredOnRoot(t *testing.T) {
	root := NewRootCmd()
	var found *cobra.Command
	for _, sub := range root.Commands() {
		if sub.Name() == "doctor" {
			found = sub
		}
	}
	require.NotNil(t, found, "doctor must be registered on the root command")
	assert.Contains(t, found.Short, "health")
}

func TestDoctorCmd_RejectsPositionalArgs(t *testing.T) {
	doctorFixture(t, doctorLocalConfig, map[string]string{".secrets.dev.yaml": doctorSecretsFile})

	_, _, err := runDoctorCmd(t, "bogus-arg")
	require.Error(t, err, "doctor takes no positional args")
}
