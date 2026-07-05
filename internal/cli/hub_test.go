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
	assert.Contains(t, err.Error(), "create request")
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
	// No prior sync for the declared dotenv target -> first-run empty state ->
	// BuildManifest marks it "missing" (the correct drift signal).
	target, ok := decoded.Keys[0].Targets["dotenv:out.env"]
	require.True(t, ok, "declared sync.targets entry must appear in the manifest")
	assert.Equal(t, "missing", target.Status)
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

// --- loadHubStates ---

func TestLoadHubStates_NilConfig(t *testing.T) {
	assert.Empty(t, loadHubStates(NewRootCmd(), nil))
}

func TestLoadHubStates_AllTargetTypes(t *testing.T) {
	setFakeHome(t)

	sc := &config.SyncConfig{Targets: []config.SyncTarget{
		{Type: "dotenv", File: "out.env"},
		{Type: "github", Repo: "o/r"},
		{Type: "cloudflare", Worker: "w"},
	}}
	states := loadHubStates(NewRootCmd(), sc)
	assert.Contains(t, states, "dotenv:out.env")
	assert.Contains(t, states, "github:o/r")
	assert.Contains(t, states, "cloudflare:worker/w")
}

// TestLoadHubStates_CorruptStateFile_WarnsAndMarksMissing covers the fix for
// a corrupt/unreadable sync-state cache: unlike the never-synced case (which
// LoadSyncState reports as an empty, non-error state), a genuine read/parse
// failure must not make the target vanish from the manifest silently. It
// should still contribute an (empty) entry -- so BuildManifest marks it
// "missing" -- and loadHubStates must warn on cmd's stderr.
func TestLoadHubStates_CorruptStateFile_WarnsAndMarksMissing(t *testing.T) {
	setFakeHome(t)

	sc := &config.SyncConfig{Targets: []config.SyncTarget{
		{Type: "dotenv", File: "out.env"},
	}}

	path, err := syncer.StatePathFor("dotenv", "out.env")
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, []byte("not json"), 0o600))

	cmd := NewRootCmd()
	var buf bytes.Buffer
	cmd.SetErr(&buf)

	states := loadHubStates(cmd, sc)
	require.Contains(t, states, "dotenv:out.env")
	assert.Empty(t, states["dotenv:out.env"].Hashes)
	assert.Contains(t, buf.String(), "warning: skipping drift for dotenv:out.env")
}
