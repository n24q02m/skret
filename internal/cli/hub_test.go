package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/n24q02m/skret/internal/config"
	"github.com/n24q02m/skret/internal/syncer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHubPush_PostsManifestNoValues(t *testing.T) {
	var gotAuth string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	m := &syncer.Manifest{Namespace: "/a/prod", Env: "prod"}
	err := postManifest(srv.URL, "hub-token", m)
	require.NoError(t, err)
	assert.Equal(t, "Bearer hub-token", gotAuth)
	var decoded syncer.Manifest
	require.NoError(t, json.Unmarshal(gotBody, &decoded))
	assert.Equal(t, "/a/prod", decoded.Namespace)
}

func TestHubPush_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	err := postManifest(srv.URL, "t", &syncer.Manifest{})
	require.ErrorContains(t, err, "403")
}

func TestPostManifest_NoTokenSkipsAuthHeader(t *testing.T) {
	var sawAuthHeader bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, sawAuthHeader = r.Header["Authorization"]
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	require.NoError(t, postManifest(srv.URL, "", &syncer.Manifest{}))
	assert.False(t, sawAuthHeader, "no token -> no Authorization header should be sent")
}

func TestPostManifest_InvalidURL_CreateRequestError(t *testing.T) {
	err := postManifest("http://%zz", "t", &syncer.Manifest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid hub URL")
}

func TestPostManifest_ConnectionRefused(t *testing.T) {
	// Grab a free loopback port, then release it immediately so nothing is
	// listening -> deterministic connection-refused without a real network call.
	lc := &net.ListenConfig{}
	l, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close())

	err = postManifest("http://"+addr, "t", &syncer.Manifest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "post:")
}

// TestPostManifest_RefusesTokenOverNonLoopbackHTTP is the hard requirement
// for the http-token-leak fix: a bearer token must never be sent in the
// clear to a non-loopback host.
func TestPostManifest_RefusesTokenOverNonLoopbackHTTP(t *testing.T) {
	err := postManifest("http://example.com", "secret-token", &syncer.Manifest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "https")
	assert.NotContains(t, err.Error(), "secret-token")
}

// TestPostManifest_AllowsTokenOverLoopbackHTTP keeps the local-hub dev
// workflow (and TestHubPush_PostsManifestNoValues, which posts a token to an
// httptest server at http://127.0.0.1:PORT) working: loopback is exempt from
// the https requirement.
func TestPostManifest_AllowsTokenOverLoopbackHTTP(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	err := postManifest(srv.URL, "loopback-token", &syncer.Manifest{})
	require.NoError(t, err)
	assert.Equal(t, "Bearer loopback-token", gotAuth)
}

// --- newHubCmd wiring ---

func TestNewHubCmd_Structure(t *testing.T) {
	cmd := newHubCmd(&GlobalOpts{})
	assert.Equal(t, "hub", cmd.Use)

	push, _, err := cmd.Find([]string{"push"})
	require.NoError(t, err)
	assert.Equal(t, "push", push.Use)
	assert.NotNil(t, push.Flags().Lookup("hub-url"))
}

func TestHubCmd_Execute_NoHubURL(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(dir+"/.git", 0o755))
	require.NoError(t, os.WriteFile(dir+"/.skret.yaml", []byte(`
version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: secrets.yaml
`), 0o644))
	require.NoError(t, os.WriteFile(dir+"/secrets.yaml", []byte("version: \"1\"\nsecrets:\n  K: V"), 0o600))

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"hub", "push"})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no hub URL")
}

// --- runPush ---

func TestHubOptions_RunPush_LoadProviderError(t *testing.T) {
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	o := &hubOptions{global: &GlobalOpts{}}
	err := o.runPush(NewRootCmd())
	assert.Error(t, err)
}

func TestHubOptions_RunPush_NoHubURL(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(dir+"/.git", 0o755))
	require.NoError(t, os.WriteFile(dir+"/.skret.yaml", []byte(`
version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: secrets.yaml
`), 0o644))
	require.NoError(t, os.WriteFile(dir+"/secrets.yaml", []byte("version: \"1\"\nsecrets:\n  K: V"), 0o600))

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	o := &hubOptions{global: &GlobalOpts{}}
	err := o.runPush(NewRootCmd())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no hub URL")
}

func setFakeHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", home)
	} else {
		t.Setenv("HOME", home)
	}
	return home
}

// TestHubOptions_RunPush_HubURLFlag_NoSecretValueInBody is the hard
// requirement: the manifest POSTed to the hub must never contain a raw
// secret value, even when the provider holds real secret data.
func TestHubOptions_RunPush_HubURLFlag_NoSecretValueInBody(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(dir+"/.git", 0o755))
	require.NoError(t, os.WriteFile(dir+"/.skret.yaml", []byte(`
version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: secrets.yaml
`), 0o644))
	require.NoError(t, os.WriteFile(dir+"/secrets.yaml", []byte("version: \"1\"\nsecrets:\n  DB_PASSWORD: SuperSecretValue123"), 0o600))

	setFakeHome(t)

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	var gotAuth string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	t.Setenv("SKRET_HUB_TOKEN", "tok-abc")

	o := &hubOptions{global: &GlobalOpts{}, hubURL: srv.URL}
	cmd := NewRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	require.NoError(t, o.runPush(cmd))
	assert.Equal(t, "Bearer tok-abc", gotAuth)
	assert.NotContains(t, string(gotBody), "SuperSecretValue123")
	assert.Contains(t, buf.String(), "Pushed manifest")

	var decoded syncer.Manifest
	require.NoError(t, json.Unmarshal(gotBody, &decoded))
	require.Len(t, decoded.Keys, 1)
	assert.Equal(t, "DB_PASSWORD", decoded.Keys[0].Name)
	assert.NotEmpty(t, decoded.Keys[0].Fingerprint)
}

func TestHubOptions_RunPush_HubURLFromSyncConfig(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(dir+"/.git", 0o755))
	cfgYAML := fmt.Sprintf(`
version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: secrets.yaml
sync:
  hub:
    url: %q
  targets:
    - type: dotenv
      file: out.env
`, srv.URL)
	require.NoError(t, os.WriteFile(dir+"/.skret.yaml", []byte(cfgYAML), 0o644))
	require.NoError(t, os.WriteFile(dir+"/secrets.yaml", []byte("version: \"1\"\nsecrets:\n  K: V"), 0o600))

	setFakeHome(t)

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	// --hub-url left empty: must fall back to sync.hub.url from .skret.yaml.
	o := &hubOptions{global: &GlobalOpts{}}
	cmd := NewRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	require.NoError(t, o.runPush(cmd))

	var decoded syncer.Manifest
	require.NoError(t, json.Unmarshal(gotBody, &decoded))
	require.Len(t, decoded.Keys, 1)
	// dotenv has no ExistingLister -- it cannot enumerate what it already
	// wrote -- so BuildManifest marks it "unknown" (the correct presence
	// signal for a target type that structurally can't answer).
	target, ok := decoded.Keys[0].Targets["dotenv:out.env"]
	require.True(t, ok, "declared sync.targets entry must appear in the manifest")
	assert.Equal(t, "unknown", target.Status)
	assert.False(t, target.Present)
}

// TestHubOptions_RunPush_HubURLFromEnv verifies the SKRET_HUB_URL env var is
// used as the hub endpoint when --hub-url is not set and no sync.hub.url is
// declared. This is what lets the cron sync container point `skret hub push`
// at the vault Worker via a forwarded env var (no flag, no baked config).
func TestHubOptions_RunPush_HubURLFromEnv(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(dir+"/.git", 0o755))
	require.NoError(t, os.WriteFile(dir+"/.skret.yaml", []byte(`
version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: secrets.yaml
`), 0o644))
	require.NoError(t, os.WriteFile(dir+"/secrets.yaml", []byte("version: \"1\"\nsecrets:\n  K: V"), 0o600))

	setFakeHome(t)
	t.Setenv("SKRET_HUB_URL", srv.URL)

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	// --hub-url left empty: must fall back to the SKRET_HUB_URL env var.
	o := &hubOptions{global: &GlobalOpts{}}
	cmd := NewRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	require.NoError(t, o.runPush(cmd))

	var decoded syncer.Manifest
	require.NoError(t, json.Unmarshal(gotBody, &decoded))
	require.Len(t, decoded.Keys, 1)
	assert.Equal(t, "K", decoded.Keys[0].Name)
}

// TestHubOptions_RunPush_FlagBeatsEnv locks the resolution precedence: an
// explicit --hub-url wins over the SKRET_HUB_URL env var.
func TestHubOptions_RunPush_FlagBeatsEnv(t *testing.T) {
	envHit := false
	envSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		envHit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer envSrv.Close()
	flagHit := false
	flagSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		flagHit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer flagSrv.Close()

	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(dir+"/.git", 0o755))
	require.NoError(t, os.WriteFile(dir+"/.skret.yaml", []byte(`
version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: secrets.yaml
`), 0o644))
	require.NoError(t, os.WriteFile(dir+"/secrets.yaml", []byte("version: \"1\"\nsecrets:\n  K: V"), 0o600))

	setFakeHome(t)
	t.Setenv("SKRET_HUB_URL", envSrv.URL)

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	o := &hubOptions{global: &GlobalOpts{}, hubURL: flagSrv.URL}
	cmd := NewRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	require.NoError(t, o.runPush(cmd))

	assert.True(t, flagHit, "--hub-url flag endpoint must receive the manifest")
	assert.False(t, envHit, "SKRET_HUB_URL env must not be used when --hub-url is set")
}

func TestHubOptions_RunPush_PostManifestError(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(dir+"/.git", 0o755))
	require.NoError(t, os.WriteFile(dir+"/.skret.yaml", []byte(`
version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: secrets.yaml
`), 0o644))
	require.NoError(t, os.WriteFile(dir+"/secrets.yaml", []byte("version: \"1\"\nsecrets:\n  K: V"), 0o600))

	setFakeHome(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	o := &hubOptions{global: &GlobalOpts{}, hubURL: srv.URL}
	err := o.runPush(NewRootCmd())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "post manifest failed")
}

func TestHubOptions_RunPush_LoadDeploySaltError(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(dir+"/.git", 0o755))
	require.NoError(t, os.WriteFile(dir+"/.skret.yaml", []byte(`
version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: secrets.yaml
`), 0o644))
	require.NoError(t, os.WriteFile(dir+"/secrets.yaml", []byte("version: \"1\"\nsecrets:\n  K: V"), 0o600))

	home := setFakeHome(t)
	// Block ~/.skret/hub-salt: a regular file sits where the .skret directory
	// needs to be created, so os.MkdirAll fails deterministically.
	require.NoError(t, os.WriteFile(filepath.Join(home, ".skret"), []byte("block"), 0o600))

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	o := &hubOptions{global: &GlobalOpts{}, hubURL: "http://example.invalid"}
	err := o.runPush(NewRootCmd())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "load deploy salt failed")
}

// --- targetPresence ---

func TestTargetPresence_NilConfig(t *testing.T) {
	assert.Empty(t, targetPresence(context.Background(), NewRootCmd(), nil))
}

// TestTargetPresence_Dotenv_Unknown_NoWarning: dotenv has no ExistingLister
// implementation at all -- this is a structural limitation, not an error,
// so it must NOT print a warning (only a genuine failure to determine
// presence warns).
func TestTargetPresence_Dotenv_Unknown_NoWarning(t *testing.T) {
	sc := &config.SyncConfig{Targets: []config.SyncTarget{{Type: "dotenv", File: "out.env"}}}
	cmd := NewRootCmd()
	var buf bytes.Buffer
	cmd.SetErr(&buf)

	presence := targetPresence(context.Background(), cmd, sc)
	require.Contains(t, presence, "dotenv:out.env")
	assert.False(t, presence["dotenv:out.env"].Ok)
	assert.Empty(t, buf.String())
}

func TestTargetPresence_GitHub_PresentAndAbsent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"total_count":1,"secrets":[{"name":"HAVE_KEY"}]}`))
	}))
	defer srv.Close()

	sc := &config.SyncConfig{Targets: []config.SyncTarget{
		{Type: "github", Repo: "o/r", BaseURL: srv.URL},
	}}
	t.Setenv("GITHUB_TOKEN", "tok")

	presence := targetPresence(context.Background(), NewRootCmd(), sc)
	require.Contains(t, presence, "github:o/r")
	got := presence["github:o/r"]
	assert.True(t, got.Ok)
	assert.True(t, got.Names["HAVE_KEY"])
	assert.False(t, got.Names["MISSING_KEY"])
}

// TestTargetPresence_GitHub_NoToken_UnknownWithWarning: the syncer can't
// even be built without GITHUB_TOKEN (newGitHubFromConfig errors) -- that
// must still degrade to "unknown" + a stderr warning, not fail the push.
func TestTargetPresence_GitHub_NoToken_UnknownWithWarning(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	sc := &config.SyncConfig{Targets: []config.SyncTarget{{Type: "github", Repo: "o/r"}}}
	cmd := NewRootCmd()
	var buf bytes.Buffer
	cmd.SetErr(&buf)

	presence := targetPresence(context.Background(), cmd, sc)
	require.Contains(t, presence, "github:o/r")
	assert.False(t, presence["github:o/r"].Ok)
	assert.Contains(t, buf.String(), "warning: hub push: github:o/r: build target failed")
	assert.Contains(t, buf.String(), "GITHUB_TOKEN")
}

func TestTargetPresence_GitHub_NetworkError_UnknownWithWarning(t *testing.T) {
	lc := &net.ListenConfig{}
	l, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close()) // nothing listening -> ExistingKeys fails

	sc := &config.SyncConfig{Targets: []config.SyncTarget{
		{Type: "github", Repo: "o/r", BaseURL: "http://" + addr},
	}}
	t.Setenv("GITHUB_TOKEN", "tok")
	cmd := NewRootCmd()
	var buf bytes.Buffer
	cmd.SetErr(&buf)

	presence := targetPresence(context.Background(), cmd, sc)
	require.Contains(t, presence, "github:o/r")
	assert.False(t, presence["github:o/r"].Ok)
	assert.Contains(t, buf.String(), "warning: hub push: github:o/r: list existing keys failed")
}

func TestTargetPresence_CloudflarePages_Unknown_WithWarning(t *testing.T) {
	sc := &config.SyncConfig{Targets: []config.SyncTarget{
		{Type: "cloudflare", Pages: "proj", Account: "acc"},
	}}
	t.Setenv("CLOUDFLARE_API_TOKEN", "tok")
	cmd := NewRootCmd()
	var buf bytes.Buffer
	cmd.SetErr(&buf)

	presence := targetPresence(context.Background(), cmd, sc)
	require.Contains(t, presence, "cloudflare:pages/proj")
	assert.False(t, presence["cloudflare:pages/proj"].Ok)
	assert.Contains(t, buf.String(), "warning: hub push: cloudflare:pages/proj: list existing keys failed")
	assert.Contains(t, buf.String(), "pages targets cannot enumerate")
}

func TestTargetPresence_CloudflareWorker_Present(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"result":[{"name":"HAVE_KEY","type":"secret_text"}]}`))
	}))
	defer srv.Close()

	sc := &config.SyncConfig{Targets: []config.SyncTarget{
		{Type: "cloudflare", Worker: "w", Account: "acc", BaseURL: srv.URL},
	}}
	t.Setenv("CLOUDFLARE_API_TOKEN", "tok")

	presence := targetPresence(context.Background(), NewRootCmd(), sc)
	require.Contains(t, presence, "cloudflare:worker/w")
	got := presence["cloudflare:worker/w"]
	assert.True(t, got.Ok)
	assert.True(t, got.Names["HAVE_KEY"])
}

// TestHubOptions_RunPush_GitHubTarget_PresentAbsentEndToEnd exercises the
// full runPush wiring: a real .skret.yaml github target (base_url pointed
// at a local httptest GitHub-API double) plus a local-provider secrets
// file with one key that "exists" on the fake GitHub side and one that
// doesn't, posted to a fake hub ingest endpoint.
func TestHubOptions_RunPush_GitHubTarget_PresentAbsentEndToEnd(t *testing.T) {
	ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"total_count":1,"secrets":[{"name":"HAVE_KEY"}]}`))
	}))
	defer ghSrv.Close()

	var gotBody []byte
	hubSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer hubSrv.Close()

	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(dir+"/.git", 0o755))
	cfgYAML := fmt.Sprintf(`
version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: secrets.yaml
sync:
  hub:
    url: %q
  targets:
    - type: github
      repo: o/r
      base_url: %q
`, hubSrv.URL, ghSrv.URL)
	require.NoError(t, os.WriteFile(dir+"/.skret.yaml", []byte(cfgYAML), 0o644))
	require.NoError(t, os.WriteFile(dir+"/secrets.yaml", []byte("version: \"1\"\nsecrets:\n  HAVE_KEY: v1\n  MISSING_KEY: v2"), 0o600))

	setFakeHome(t)
	t.Setenv("GITHUB_TOKEN", "tok")

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	o := &hubOptions{global: &GlobalOpts{}}
	require.NoError(t, o.runPush(NewRootCmd()))

	var decoded syncer.Manifest
	require.NoError(t, json.Unmarshal(gotBody, &decoded))
	byName := map[string]syncer.ManifestTarget{}
	for _, k := range decoded.Keys {
		byName[k.Name] = k.Targets["github:o/r"]
	}
	assert.Equal(t, "present", byName["HAVE_KEY"].Status)
	assert.True(t, byName["HAVE_KEY"].Present)
	assert.Equal(t, "absent", byName["MISSING_KEY"].Status)
	assert.False(t, byName["MISSING_KEY"].Present)
	assert.NotContains(t, string(gotBody), "v1")
	assert.NotContains(t, string(gotBody), "v2")
}
