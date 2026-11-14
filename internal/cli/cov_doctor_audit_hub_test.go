package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/n24q02m/skret/internal/auth"
	"github.com/n24q02m/skret/internal/config"
	"github.com/n24q02m/skret/internal/provider"
	"github.com/n24q02m/skret/pkg/skret"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// covBIsolateAWS points the AWS SDK at a hermetic setup: a scratch home (so
// no skret-stored credential or ~/.aws file is read), static fake keys, a
// fixed region, and the given service-specific endpoint env var aimed at a
// local httptest server. Nothing here can reach a real AWS endpoint.
func covBIsolateAWS(t *testing.T, endpointEnv, endpoint string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("SKRET_KEYRING", "")
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(home, "aws-config-absent"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(home, "aws-credentials-absent"))
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_DEFAULT_PROFILE", "")
	t.Setenv("SKRET_PROFILE", "")
	t.Setenv("SKRET_REGION", "")
	t.Setenv("SKRET_ENV", "")
	t.Setenv("SKRET_PROVIDER", "")
	t.Setenv("SKRET_PATH", "")
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDCOVBTEST")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "covb-test-secret")
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_ENDPOINT_URL", "")
	if endpointEnv != "" {
		t.Setenv(endpointEnv, endpoint)
	}
}

// covBAWSConfig is a minimal aws environment for the audit dispatch tests.
const covBAWSConfig = "version: \"1\"\ndefault_env: dev\nenvironments:\n  dev:\n    provider: aws\n    path: /app/dev\n    region: us-east-1\n"

// covBCloudTrail is a fake CloudTrail LookupEvents endpoint. It answers
// PutParameter lookups with the given events and every other event name with
// an empty page; status != 200 answers every call with a client error.
type covBCloudTrail struct {
	mu      sync.Mutex
	targets []string
	names   []string
}

func (c *covBCloudTrail) server(t *testing.T, status int, putEvents string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var in struct {
			LookupAttributes []struct {
				AttributeKey   string
				AttributeValue string
			}
		}
		_ = json.Unmarshal(body, &in)
		name := ""
		if len(in.LookupAttributes) > 0 {
			name = in.LookupAttributes[0].AttributeValue
		}
		c.mu.Lock()
		c.targets = append(c.targets, r.Header.Get("X-Amz-Target"))
		c.names = append(c.names, name)
		c.mu.Unlock()

		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		if status != http.StatusOK {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"__type":"InvalidLookupAttributesException","message":"covb rejected lookup"}`))
			return
		}
		if name == "PutParameter" {
			_, _ = w.Write([]byte(`{"Events":` + putEvents + `}`))
			return
		}
		_, _ = w.Write([]byte(`{"Events":[]}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// covBCloudTrailEvent renders one LookupEvents entry for an SSM PutParameter.
func covBCloudTrailEvent(id string, epoch int64, param, user, ip string) string {
	envelope, _ := json.Marshal(map[string]any{
		"eventName":         "PutParameter",
		"eventSource":       "ssm.amazonaws.com",
		"awsRegion":         "us-east-1",
		"sourceIPAddress":   ip,
		"userName":          user,
		"requestParameters": map[string]string{"name": param},
	})
	ev, _ := json.Marshal(map[string]any{
		"EventId":         id,
		"EventName":       "PutParameter",
		"EventTime":       epoch,
		"CloudTrailEvent": string(envelope),
	})
	return string(ev)
}

func covBAWSAuditRepo(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".skret.yaml"), []byte(covBAWSConfig), 0o600))
	chdirTmp(t, dir)
}

// --- audit: aws provider renders CloudTrail events ---

func TestCovBAuditCmd_AWS_TableAndJSON(t *testing.T) {
	ct := &covBCloudTrail{}
	events := "[" +
		covBCloudTrailEvent("ev-old", 1767225600, "/app/dev/API_KEY", "alice", "10.0.0.1") + "," + // 2026-01-01T00:00:00Z
		covBCloudTrailEvent("ev-new", 1767312000, "/app/dev/DB_URL", "bob", "10.0.0.2") + // 2026-01-02T00:00:00Z
		"]"
	srv := ct.server(t, http.StatusOK, events)
	covBIsolateAWS(t, "AWS_ENDPOINT_URL_CLOUDTRAIL", srv.URL)
	covBAWSAuditRepo(t)

	stdout, _, err := runAudit(t)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
	require.Len(t, lines, 3, "header + one row per CloudTrail event: %q", stdout)
	assert.Equal(t, []string{"TIME", "EVENT", "PARAMETER", "USER", "SOURCE"}, strings.Fields(lines[0]))
	// Newest first, timestamps rendered at second precision in UTC.
	assert.Equal(t, []string{"2026-01-02T00:00:00Z", "PutParameter", "/app/dev/DB_URL", "bob", "10.0.0.2"}, strings.Fields(lines[1]))
	assert.Equal(t, []string{"2026-01-01T00:00:00Z", "PutParameter", "/app/dev/API_KEY", "alice", "10.0.0.1"}, strings.Fields(lines[2]))

	ct.mu.Lock()
	require.NotEmpty(t, ct.targets)
	assert.Equal(t, "CloudTrail_20131101.LookupEvents", ct.targets[0])
	assert.Contains(t, ct.names, "PutParameter")
	assert.Contains(t, ct.names, "GetParametersByPath")
	ct.mu.Unlock()

	stdout, _, err = runAudit(t, "--format", "json", "--key", "/app/dev/API_KEY")
	require.NoError(t, err)
	var got []map[string]string
	require.NoError(t, json.Unmarshal([]byte(stdout), &got))
	require.Len(t, got, 1, "--key filters to the exact parameter")
	assert.Equal(t, "/app/dev/API_KEY", got[0]["parameter"])
	assert.Equal(t, "alice", got[0]["username"])
	assert.Equal(t, "ev-old", got[0]["event_id"])
	assert.Equal(t, "2026-01-01T00:00:00Z", got[0]["time"])
}

func TestCovBAuditCmd_AWS_NoEvents(t *testing.T) {
	ct := &covBCloudTrail{}
	srv := ct.server(t, http.StatusOK, "[]")
	covBIsolateAWS(t, "AWS_ENDPOINT_URL_CLOUDTRAIL", srv.URL)
	covBAWSAuditRepo(t)

	stdout, stderr, err := runAudit(t)
	require.NoError(t, err)
	assert.Empty(t, stdout, "table mode prints nothing on stdout without events")
	assert.Contains(t, stderr, "No CloudTrail events found")

	stdout, stderr, err = runAudit(t, "--format", "json")
	require.NoError(t, err)
	assert.Equal(t, "[]", strings.TrimSpace(stdout), "json mode always emits an array")
	assert.Contains(t, stderr, "No CloudTrail events found")
}

func TestCovBAuditCmd_AWS_LookupFailureIsProviderError(t *testing.T) {
	ct := &covBCloudTrail{}
	srv := ct.server(t, http.StatusBadRequest, "")
	covBIsolateAWS(t, "AWS_ENDPOINT_URL_CLOUDTRAIL", srv.URL)
	covBAWSAuditRepo(t)

	_, _, err := runAudit(t)
	require.Error(t, err)
	assert.Equal(t, skret.ExitProviderError, skret.ExitCode(err))
	assert.Contains(t, err.Error(), "audit: cloudtrail lookup failed")
	assert.Contains(t, err.Error(), "covb rejected lookup")
}

func TestCovBAuditCmd_AWS_ClientInitFailure(t *testing.T) {
	covBIsolateAWS(t, "", "")
	covBAWSAuditRepo(t)

	// A named profile absent from the (empty) shared config fails client
	// construction before any request is attempted.
	_, _, err := runAudit(t, "--profile", "covb-no-such-profile")
	require.Error(t, err)
	assert.Equal(t, skret.ExitProviderError, skret.ExitCode(err))
	assert.Contains(t, err.Error(), "audit: init cloudtrail client failed")
}

// --- audit: local trail and config resolution edges ---

func TestCovBAuditCmd_LocalTrailUnreadable(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".skret.yaml"), []byte(
		"version: \"1\"\ndefault_env: dev\nenvironments:\n  dev:\n    provider: local\n    file: dev.yaml\n    audit_log: trail-dir\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "dev.yaml"), []byte("version: \"1\"\nsecrets:\n  K: v\n"), 0o600))
	// The configured trail path is a directory: reading it fails with an
	// error that is not "does not exist", so it must surface, not be
	// mistaken for an empty trail.
	require.NoError(t, os.Mkdir(filepath.Join(dir, "trail-dir"), 0o700))
	chdirTmp(t, dir)

	_, _, err := runAudit(t)
	require.Error(t, err)
	assert.Equal(t, skret.ExitProviderError, skret.ExitCode(err))
	assert.Contains(t, err.Error(), "audit: read")
	assert.Contains(t, err.Error(), "trail-dir")
}

func TestCovBAuditTableTime_UnparseableVerbatim(t *testing.T) {
	assert.Equal(t, "not-a-time", auditTableTime("not-a-time"))
	assert.Equal(t, "2026-01-02T03:04:05Z", auditTableTime("2026-01-02T05:04:05.123+02:00"))
}

func TestCovBLoadResolvedConfig_Branches(t *testing.T) {
	t.Setenv("SKRET_ENV", "")
	t.Setenv("SKRET_PROVIDER", "")
	t.Setenv("SKRET_PATH", "")

	t.Run("malformed config is a config error", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, ".skret.yaml"), []byte("version: [unclosed\n"), 0o600))
		chdirTmp(t, dir)
		_, err := loadResolvedConfig(&GlobalOpts{})
		require.Error(t, err)
		assert.Equal(t, skret.ExitConfigError, skret.ExitCode(err))
		assert.Contains(t, err.Error(), "load config failed")
	})

	t.Run("explicit --config that is missing", func(t *testing.T) {
		chdirTmp(t, t.TempDir())
		_, err := loadResolvedConfig(&GlobalOpts{Config: filepath.Join(t.TempDir(), "absent.yaml")})
		require.Error(t, err)
		assert.Equal(t, skret.ExitConfigError, skret.ExitCode(err))
		assert.Contains(t, err.Error(), "load config failed")
	})

	t.Run("no config but --path builds an ephemeral config", func(t *testing.T) {
		chdirTmp(t, t.TempDir())
		resolved, err := loadResolvedConfig(&GlobalOpts{Path: "/app/prod"})
		require.NoError(t, err)
		assert.Equal(t, "/app/prod", resolved.Path)
		assert.Equal(t, "aws", resolved.Provider)
	})

	t.Run("unknown env fails resolution", func(t *testing.T) {
		dir := writeLocalTemplateConfig(t)
		chdirTmp(t, dir)
		_, err := loadResolvedConfig(&GlobalOpts{Env: "covb-missing"})
		require.Error(t, err)
		assert.Equal(t, skret.ExitConfigError, skret.ExitCode(err))
		assert.Contains(t, err.Error(), "resolve config failed")
	})
}

// --- doctor: real AWS permission probe against a fake SSM endpoint ---

func TestCovBDoctorAWSPermissionProbe_SentinelKey(t *testing.T) {
	var (
		mu    sync.Mutex
		names []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Name string }
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &in)
		mu.Lock()
		names = append(names, r.Header.Get("X-Amz-Target")+" "+in.Name)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"__type":"ParameterNotFound","message":"covb: no such parameter"}`))
	}))
	t.Cleanup(srv.Close)
	covBIsolateAWS(t, "AWS_ENDPOINT_URL_SSM", srv.URL)

	// Under an environment path the sentinel is <path>/skret-doctor-probe;
	// a not-found answer proves the read was allowed.
	check := doctorAWSPermissionCheck("prod", &config.ResolvedConfig{Provider: "aws", Path: "/app/prod", Region: "us-east-1"}, 5*time.Second)
	assert.Equal(t, doctorPass, check.Status, check.Detail)
	assert.Contains(t, check.Detail, "sentinel probe: not found, no denial")

	// An empty path probes the bare sentinel name.
	err := doctorAWSPermissionProbe(context.Background(), &config.ResolvedConfig{Provider: "aws", Region: "us-east-1"})
	require.ErrorIs(t, err, provider.ErrNotFound)

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, []string{
		"AmazonSSM.GetParameter /app/prod/skret-doctor-probe",
		"AmazonSSM.GetParameter skret-doctor-probe",
	}, names)
}

func TestCovBDoctorAWSPermissionProbe_ClientInitFailure(t *testing.T) {
	covBIsolateAWS(t, "", "")
	err := doctorAWSPermissionProbe(context.Background(),
		&config.ResolvedConfig{Provider: "aws", Path: "/app/prod", Region: "us-east-1", Profile: "covb-no-such-profile"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "covb-no-such-profile")

	// The same failure through the check is inconclusive (warn), not a denial.
	check := doctorAWSPermissionCheck("prod",
		&config.ResolvedConfig{Provider: "aws", Path: "/app/prod", Region: "us-east-1", Profile: "covb-no-such-profile"}, time.Second)
	assert.Equal(t, doctorWarn, check.Status)
	assert.Contains(t, check.Detail, "inconclusive read probe")
}

func TestCovBDoctorAWSPermissionCheck_SentinelPresentPasses(t *testing.T) {
	orig := doctorAWSPermissionProbe
	t.Cleanup(func() { doctorAWSPermissionProbe = orig })
	doctorAWSPermissionProbe = func(context.Context, *config.ResolvedConfig) error { return nil }

	check := doctorAWSPermissionCheck("prod", &config.ResolvedConfig{Path: "/app/prod"}, time.Second)
	assert.Equal(t, "permissions[prod]", check.Name)
	assert.Equal(t, doctorPass, check.Status)
	assert.Equal(t, "can read under /app/prod (sentinel key present)", check.Detail)
	assert.Empty(t, check.Remediation)
}

// --- doctor: provider dispatch for azure / oci / gcp / unknown ---

func TestCovBDoctorCmd_DispatchesEveryProvider(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("SKRET_ENV", "")
	t.Setenv("SKRET_PROVIDER", "")
	for _, key := range []string{
		"OCI_CLI_AUTH", "OCI_CLI_USER", "OCI_CLI_TENANCY", "OCI_CLI_FINGERPRINT",
		"OCI_CLI_KEY_FILE", "OCI_CLI_PASS_PHRASE", "OCI_CLI_REGION",
		"OCI_CLI_PROFILE", "OCI_CLI_CONFIG_FILE",
	} {
		t.Setenv(key, "")
	}
	origGCP := doctorGCPProbe
	t.Cleanup(func() { doctorGCPProbe = origGCP })
	var gcpProject string
	doctorGCPProbe = func(_ context.Context, r *config.ResolvedConfig) error {
		gcpProject = r.Project
		return nil
	}

	// azure: an invalid vault_name fails provider construction (config
	// class) before any credential or network use; oci: no ~/.oci config
	// in the scratch home (auth class); gcp: stubbed probe passes.
	doctorFixture(t, `version: "1"
default_env: gcp
environments:
  az:
    provider: azure
    vault_name: "x"
  gcp:
    provider: gcp
    project: covb-project
  oci:
    provider: oci
    compartment_id: ocid1.compartment.oc1..covb
    vault_id: ocid1.vault.oc1..covb
`, nil)

	stdout, stderr, err := runDoctorCmd(t, "--format", "json")
	require.Error(t, err)
	// Precedence: the azure config-class failure wins over oci's auth class.
	assert.Equal(t, skret.ExitConfigError, skret.ExitCode(err))
	assert.Empty(t, stderr)

	var report doctorReport
	require.NoError(t, json.Unmarshal([]byte(stdout), &report))
	byName := map[string]DoctorCheck{}
	for _, c := range report.Checks {
		byName[c.Name] = c
	}
	require.Contains(t, byName, "provider[az]")
	assert.Equal(t, doctorFail, byName["provider[az]"].Status)
	assert.Contains(t, byName["provider[az]"].Remediation, "vault_url")
	require.Contains(t, byName, "provider[gcp]")
	assert.Equal(t, doctorPass, byName["provider[gcp]"].Status)
	assert.Equal(t, "covb-project", gcpProject)
	require.Contains(t, byName, "provider[oci]")
	assert.Equal(t, doctorFail, byName["provider[oci]"].Status)
	assert.Contains(t, byName["provider[oci]"].Detail, "auth configuration unusable")
}

func TestCovBDoctorCmd_UnknownProviderOverride(t *testing.T) {
	t.Setenv("SKRET_ENV", "")
	t.Setenv("SKRET_PROVIDER", "")
	doctorFixture(t, doctorLocalConfig, map[string]string{".secrets.dev.yaml": doctorSecretsFile})

	_, stderr, err := runDoctorCmd(t, "--provider", "vault")
	require.Error(t, err)
	assert.Equal(t, skret.ExitConfigError, skret.ExitCode(err))
	assert.Contains(t, stderr, `FAIL provider[dev]: unknown provider "vault"`)
	assert.Contains(t, stderr, "fix: supported providers: local, aws, azure, oci, gcp")
}

// --- doctor: azure / oci result classification from the shared probe cache ---

func TestCovBDoctorAzureReachCheck_CachedResults(t *testing.T) {
	resolved := &config.ResolvedConfig{Provider: "azure", VaultURL: "https://covb-vault.vault.azure.net/"}
	cacheKey := "azure:" + resolved.VaultURL + "|" + resolved.VaultName

	tests := []struct {
		name      string
		probe     error
		status    string
		class     int
		detail    string
		remediate string
	}{
		{"reachable", nil, doctorPass, 0, "reachable (Key Vault list)", ""},
		{
			"vault 403 is auth class", &azcore.ResponseError{StatusCode: http.StatusForbidden, ErrorCode: "Forbidden"},
			doctorFail, skret.ExitAuthError, "credentials rejected", "DefaultAzureCredential",
		},
		{
			"vault 401 is auth class", &azcore.ResponseError{StatusCode: http.StatusUnauthorized},
			doctorFail, skret.ExitAuthError, "credentials rejected", "az login",
		},
		{
			"credential chain failure is auth class", &azidentity.AuthenticationFailedError{},
			doctorFail, skret.ExitAuthError, "credentials rejected", "AZURE_TENANT_ID",
		},
		{
			"vault 500 is network class", &azcore.ResponseError{StatusCode: http.StatusInternalServerError},
			doctorFail, skret.ExitNetworkError, "unreachable", "vault_url",
		},
		{
			"transport failure is network class", errors.New("dial tcp: covb no route"),
			doctorFail, skret.ExitNetworkError, "unreachable: dial tcp: covb no route", "check network access",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// A pre-populated cache entry is what a second azure environment
			// on the same vault sees: the probe is never re-issued.
			cache := map[string]error{cacheKey: tt.probe}
			checks := doctorAzureReachCheck("prod", time.Second, cache, resolved)
			require.Len(t, checks, 1)
			c := checks[0]
			assert.Equal(t, "provider[prod]", c.Name)
			assert.Equal(t, tt.status, c.Status)
			assert.Equal(t, tt.class, c.failClass)
			assert.Contains(t, c.Detail, tt.detail)
			if tt.remediate == "" {
				assert.Empty(t, c.Remediation)
			} else {
				assert.Contains(t, c.Remediation, tt.remediate)
			}
			assert.Len(t, cache, 1, "a cached result must not add a probe entry")
		})
	}
}

func TestCovBIsAzureAuthError(t *testing.T) {
	assert.True(t, isAzureAuthError(&azcore.ResponseError{StatusCode: 401}))
	assert.True(t, isAzureAuthError(&azcore.ResponseError{StatusCode: 403}))
	assert.False(t, isAzureAuthError(&azcore.ResponseError{StatusCode: 404}))
	wrapped := errors.Join(errors.New("context"), &azidentity.AuthenticationFailedError{})
	assert.True(t, isAzureAuthError(wrapped), "wrapped credential failures still classify as auth")
	assert.False(t, isAzureAuthError(errors.New("dial tcp: timeout")))
}

func TestCovBDoctorOCIReachCheck_CachedResults(t *testing.T) {
	resolved := &config.ResolvedConfig{Provider: "oci", Path: "/app/prod"}

	checks := doctorOCIReachCheck("prod", resolved, time.Second, map[string]error{"oci": nil})
	require.Len(t, checks, 1)
	assert.Equal(t, doctorPass, checks[0].Status)
	assert.Equal(t, "reachable (names-only listing)", checks[0].Detail)

	checks = doctorOCIReachCheck("prod", resolved, time.Second, map[string]error{"oci": errors.New("i/o timeout")})
	require.Len(t, checks, 1)
	assert.Equal(t, doctorFail, checks[0].Status)
	assert.Equal(t, skret.ExitNetworkError, checks[0].failClass)
	assert.Equal(t, "unreachable: i/o timeout", checks[0].Detail)
	assert.Contains(t, checks[0].Remediation, "OCI_CLI_REGION")
}

func TestCovBOCIAuthConfigError_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("covb: can not create client, bad configuration")
	var err error = &ociAuthConfigError{err: inner}
	assert.Equal(t, inner.Error(), err.Error())
	assert.ErrorIs(t, err, inner)
	assert.Same(t, inner, errors.Unwrap(err))
}

// --- doctor: perm check on the non-windows path (what CI's linux run takes) ---

func TestCovBDoctorPermCheck_UnixPath(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.yaml")
	c := doctorPermCheck("linux", "dev", missing)
	assert.Equal(t, "permissions[dev]", c.Name)
	assert.Equal(t, doctorWarn, c.Status)
	assert.Contains(t, c.Detail, "stat failed")

	path := filepath.Join(t.TempDir(), "secrets.yaml")
	require.NoError(t, os.WriteFile(path, []byte("version: \"1\"\n"), 0o600))
	if runtime.GOOS == "windows" {
		// Windows reports a synthetic 0666 for any writable file, so the
		// unix decision flags it as group/world accessible.
		c = doctorPermCheck("linux", "dev", path)
		assert.Equal(t, doctorWarn, c.Status)
		assert.Contains(t, c.Detail, "0666")
		assert.Contains(t, c.Remediation, "chmod 600")
		return
	}
	require.NoError(t, os.Chmod(path, 0o600))
	c = doctorPermCheck("linux", "dev", path)
	assert.Equal(t, doctorPass, c.Status)
	assert.Equal(t, "mode 0600", c.Detail)
	assert.Empty(t, c.Remediation)

	require.NoError(t, os.Chmod(path, 0o640))
	c = doctorPermCheck("linux", "dev", path)
	assert.Equal(t, doctorWarn, c.Status)
	assert.Equal(t, "file mode 0640 is group/world accessible", c.Detail)
	assert.Equal(t, "chmod 600 (the secrets file should be owner-only, not 0640)", c.Remediation)
}

// --- doctor: auth check edges ---

func TestCovBDoctorAuthCheck_UnreadableStoreAndNoExpiry(t *testing.T) {
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)

	t.Run("corrupt credential file fails auth class", func(t *testing.T) {
		storePath := filepath.Join(t.TempDir(), "credentials.yaml")
		require.NoError(t, os.WriteFile(storePath, []byte("credentials: [not, a: mapping\n"), 0o600))
		deps := doctorDeps{store: auth.NewStoreWithPath(storePath), now: func() time.Time { return now }}
		c := doctorAuthCheck(deps)
		assert.Equal(t, "auth[aws]", c.Name)
		assert.Equal(t, doctorFail, c.Status)
		assert.Equal(t, skret.ExitAuthError, c.failClass)
		assert.Contains(t, c.Detail, "credential store unreadable")
		assert.Contains(t, c.Remediation, "fix the skret credential file")
	})

	t.Run("credential without expiry passes", func(t *testing.T) {
		store := auth.NewStoreWithPath(filepath.Join(t.TempDir(), "credentials.yaml"))
		require.NoError(t, store.Save(&auth.Credential{Provider: "aws", Method: "access-key", Token: "covb-placeholder"}))
		c := doctorAuthCheck(doctorDeps{store: store, now: func() time.Time { return now }})
		assert.Equal(t, doctorPass, c.Status)
		assert.Equal(t, "valid (method: access-key)", c.Detail)
	})
}

// --- doctor: unused-key detection with nested key names ---

func TestCovBDoctorUnusedCheck_NestedKeyNames(t *testing.T) {
	dir := t.TempDir()
	trail := filepath.Join(dir, "trail.log")
	require.NoError(t, os.WriteFile(trail, []byte(strings.Join([]string{
		`{"timestamp":"2026-01-01T00:00:00Z","op":"set","key_names":["/app/dev/team/USED_NESTED"],"env":"dev","actor":"t"}`,
		`{"timestamp":"2026-01-02T00:00:00Z","op":"set","key_names":["PLAIN"],"env":"dev","actor":"t"}`,
	}, "\n")+"\n"), 0o600))
	resolved := &config.ResolvedConfig{Provider: "local", Path: "/app/dev", File: filepath.Join(dir, "dev.yaml"), AuditLog: trail}

	secrets := []*provider.Secret{
		{Key: "/app/dev/team/USED_NESTED"}, // exact key match
		{Key: "/other/USED_NESTED"},        // matched through the last path segment
		{Key: "PLAIN"},
		{Key: "/app/dev/svc/STALE"}, // nested and never mutated
	}
	c := doctorUnusedCheck("dev", secrets, resolved)
	require.NotNil(t, c)
	assert.Equal(t, "unused[dev]", c.Name)
	assert.Equal(t, doctorWarn, c.Status)
	assert.Equal(t, "1 of 4 key(s) never appear in the local audit trail (since 2026-01-01T00:00:00Z): STALE", c.Detail)
}

// --- doctor: loose environment re-read is best-effort ---

func TestCovBLoadRawEnvironments_BestEffort(t *testing.T) {
	assert.Nil(t, loadRawEnvironments(filepath.Join(t.TempDir(), "absent.yaml")))

	bad := filepath.Join(t.TempDir(), "bad.yaml")
	require.NoError(t, os.WriteFile(bad, []byte("environments: [unclosed\n"), 0o600))
	assert.Nil(t, loadRawEnvironments(bad))

	good := filepath.Join(t.TempDir(), "good.yaml")
	require.NoError(t, os.WriteFile(good, []byte("environments:\n  dev:\n    encrypted: true\n"), 0o600))
	envs := loadRawEnvironments(good)
	require.Contains(t, envs, "dev")
	assert.Equal(t, true, envs["dev"]["encrypted"])
}

// --- hub ---

func TestCovBHubSyncerStub_Names(t *testing.T) {
	cases := map[string]string{
		"github":     "github",
		"cloudflare": "cloudflare",
		"gitlab":     "gitlab",
		"terraform":  "terraform",
		"k8s":        "k8s",
		"dotenv":     "dotenv",
		"covb-other": "dotenv",
	}
	for typ, want := range cases {
		assert.Equal(t, want, hubSyncerStub(typ).Name(), "stub for %q", typ)
	}
}

func TestCovBHubInit_ConfigEdges(t *testing.T) {
	t.Setenv("SKRET_ENV", "")
	t.Setenv("SKRET_PATH", "")

	run := func(t *testing.T, args ...string) (string, error) {
		t.Helper()
		var buf bytes.Buffer
		cmd := NewRootCmd()
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)
		cmd.SetArgs(append([]string{"hub", "init", "--url", "https://vault.example.com"}, args...))
		err := cmd.Execute()
		return buf.String(), err
	}
	repo := func(t *testing.T, cfg string) string {
		t.Helper()
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, ".skret.yaml"), []byte(cfg), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "secrets.yaml"), []byte("version: \"1\"\nsecrets:\n  K: V\n"), 0o600))
		chdirTmp(t, dir)
		return dir
	}

	t.Run("malformed config", func(t *testing.T) {
		repo(t, "version: [unclosed\n")
		_, err := run(t, "--namespace", "/x")
		require.Error(t, err)
		assert.Equal(t, skret.ExitConfigError, skret.ExitCode(err))
		assert.Contains(t, err.Error(), "hub init: load config failed")
	})

	t.Run("no path and no --namespace", func(t *testing.T) {
		dir := repo(t, "version: \"1\"\ndefault_env: dev\nenvironments:\n  dev:\n    provider: local\n    file: secrets.yaml\n")
		before, _ := os.ReadFile(filepath.Join(dir, ".skret.yaml"))
		_, err := run(t)
		require.Error(t, err)
		assert.Equal(t, skret.ExitConfigError, skret.ExitCode(err))
		assert.Contains(t, err.Error(), "could not resolve a default namespace")
		assert.Contains(t, skret.RemediationOf(err), "--namespace")
		after, _ := os.ReadFile(filepath.Join(dir, ".skret.yaml"))
		assert.Equal(t, string(before), string(after), "a failed init must not rewrite the config")
	})

	t.Run("backup cannot be written", func(t *testing.T) {
		dir := repo(t, "version: \"1\"\ndefault_env: dev\nenvironments:\n  dev:\n    provider: local\n    file: secrets.yaml\n")
		// A non-empty directory squatting on the .bak path cannot be
		// replaced, so the atomic write must fail and leave the config as is.
		bak := filepath.Join(dir, ".skret.yaml.bak")
		require.NoError(t, os.MkdirAll(filepath.Join(bak, "occupied"), 0o700))
		before, _ := os.ReadFile(filepath.Join(dir, ".skret.yaml"))
		_, err := run(t, "--namespace", "/myapp/dev")
		require.Error(t, err)
		assert.Equal(t, skret.ExitGenericError, skret.ExitCode(err))
		assert.Contains(t, err.Error(), "hub init: write config failed")
		after, _ := os.ReadFile(filepath.Join(dir, ".skret.yaml"))
		assert.Equal(t, string(before), string(after))
	})
}

func TestCovBHubStatus_ConfigAndResponseEdges(t *testing.T) {
	t.Setenv("SKRET_HUB_URL", "")
	t.Setenv("SKRET_HUB_TOKEN", "")

	t.Run("malformed config fails before any request", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, ".skret.yaml"), []byte("version: [unclosed\n"), 0o600))
		chdirTmp(t, dir)
		var buf bytes.Buffer
		cmd := NewRootCmd()
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)
		cmd.SetArgs([]string{"hub", "status", "--hub-url", "http://127.0.0.1:1"})
		err := cmd.Execute()
		require.Error(t, err)
		assert.Equal(t, skret.ExitConfigError, skret.ExitCode(err))
		assert.Contains(t, err.Error(), "hub status: load config failed")
	})

	t.Run("unparseable hub url is a config error", func(t *testing.T) {
		_, err := fetchHubStatus("http://[::1", "")
		require.Error(t, err)
		assert.Equal(t, skret.ExitConfigError, skret.ExitCode(err))
		assert.Contains(t, err.Error(), "parse hub url")
	})

	t.Run("non-auth error status keeps body and is network class", func(t *testing.T) {
		var sawAuth, sawPath string
		srv := statusWorker(t, http.StatusBadGateway, "covb upstream down", &sawAuth, &sawPath)
		defer srv.Close()
		_, err := fetchHubStatus(srv.URL, "")
		require.Error(t, err)
		assert.Equal(t, skret.ExitNetworkError, skret.ExitCode(err))
		assert.Contains(t, err.Error(), "hub returned 502: covb upstream down")
		assert.Empty(t, sawAuth, "no token means no Authorization header")
	})

	t.Run("invalid json body is network class", func(t *testing.T) {
		var sawAuth, sawPath string
		srv := statusWorker(t, http.StatusOK, "{not json", &sawAuth, &sawPath)
		defer srv.Close()
		_, err := fetchHubStatus(srv.URL, "")
		require.Error(t, err)
		assert.Equal(t, skret.ExitNetworkError, skret.ExitCode(err))
		assert.Contains(t, err.Error(), "decode status response")
	})

	t.Run("missing namespaces decode as an empty list", func(t *testing.T) {
		var sawAuth, sawPath string
		srv := statusWorker(t, http.StatusOK, `{"ok":true,"namespace_count":0,"key_count":0}`, &sawAuth, &sawPath)
		defer srv.Close()
		st, err := fetchHubStatus(srv.URL, "")
		require.NoError(t, err)
		require.NotNil(t, st.Namespaces)
		assert.Empty(t, st.Namespaces)

		data, err := json.Marshal(st)
		require.NoError(t, err)
		assert.Contains(t, string(data), `"namespaces":[]`, "json output never renders null")
	})
}
