package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/n24q02m/skret/internal/secretlaunch"
)

func writeSupervisorFixtureFiles(t *testing.T) (string, string, string) {
	t.Helper()
	dir := t.TempDir()
	public, private, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	executableBytes, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	executableSHA := sha256.Sum256(executableBytes)
	now := time.Now()
	environment := map[string]string{"LOG_LEVEL": "info"}
	child := secretlaunch.ChildSpec{
		Argv: []string{"/bin/echo", "ok"}, User: "current", Environment: environment,
	}
	service := secretlaunch.ServiceSpec{
		Name:          "api",
		Image:         "registry.example/api@sha256:" + strings.Repeat("1", 64),
		User:          "1000:1000",
		Argv:          []string{"/usr/local/bin/skret-secret-helper", "--runtime", "docker-run", "--service", "api"},
		Environment:   environment,
		Labels:        map[string]string{"com.example.component": "api"},
		Networks:      []string{"backend"},
		Restart:       "no",
		OpenStdin:     true,
		Health:        secretlaunch.HealthSpec{Command: []string{"/bin/true"}, IntervalMS: 30_000, TimeoutMS: 5_000, Retries: 1, HeartbeatIntervalMS: 1_000, HeartbeatTimeoutMS: 5_000},
		Dependencies:  []string{},
		SecretKeys:    []string{"APP_TOKEN"},
		WrapperDigest: "sha256:" + strings.Repeat("3", 64),
		Child:         child,
	}
	modelDoc := secretlaunch.RenderedModel{RuntimeID: "docker-run", Services: []secretlaunch.ServiceSpec{service}}
	modelDoc.ComposeDigest, err = secretlaunch.ModelDigest(modelDoc)
	if err != nil {
		t.Fatal(err)
	}
	authority := secretlaunch.ServiceAuthority{
		Name: service.Name, Image: service.Image, User: service.User, Argv: service.Argv,
		Environment: service.Environment, Labels: service.Labels, Networks: service.Networks,
		Restart: service.Restart, OpenStdin: service.OpenStdin, Health: service.Health,
		Dependencies:  service.Dependencies,
		Keys:          []secretlaunch.ManifestKey{{Name: "APP_TOKEN", Version: "1", Env: "APP_TOKEN"}},
		WrapperDigest: service.WrapperDigest, Child: child,
	}
	manifest := secretlaunch.Manifest{
		Version:    secretlaunch.ManifestVersion,
		RuntimeID:  "docker-run",
		Role:       "prod-api",
		Generation: 1,
		IssuedAt:   now.Add(-time.Minute).Unix(),
		ExpiresAt:  now.Add(10 * time.Minute).Unix(),
		Nonce:      "nonce-1234567890",
		Services:   []secretlaunch.ServiceAuthority{authority},
		Digests: secretlaunch.ArtifactDigests{
			Helper:     "sha256:" + strings.Repeat("1", 64),
			Supervisor: fmt.Sprintf("sha256:%x", executableSHA[:]),
			Compose:    modelDoc.ComposeDigest,
		},
	}
	signedBytes, err := secretlaunch.SignManifest(manifest, "key-1", private, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(manifestPath, signedBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	trustDoc := secretlaunch.TrustDocument{
		Keys:        map[string]string{"key-1": base64.StdEncoding.EncodeToString(public)},
		Versions:    []string{secretlaunch.ManifestVersion},
		RuntimeIDs:  []string{manifest.RuntimeID},
		Roles:       []string{manifest.Role},
		KeyVersions: map[string]map[string]bool{"APP_TOKEN": {"1": true}},
	}
	trustBytes, err := json.Marshal(trustDoc)
	if err != nil {
		t.Fatal(err)
	}
	trustPath := filepath.Join(dir, "trust.json")
	if err := os.WriteFile(trustPath, trustBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	modelBytes, err := json.Marshal(modelDoc)
	if err != nil {
		t.Fatal(err)
	}
	composePath := filepath.Join(dir, "compose.json")
	if err := os.WriteFile(composePath, modelBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return manifestPath, trustPath, composePath
}

func TestSupervisorCLIRejectsImplicitDockerCall(t *testing.T) {
	manifestPath, trustPath, composePath := writeSupervisorFixtureFiles(t)
	var diagnostics bytes.Buffer
	code := run([]string{"--manifest", manifestPath, "--trust", trustPath, "--runtime", "docker-run", "--compose", composePath}, &diagnostics, nil, nil)
	if code != 2 || !strings.Contains(diagnostics.String(), string(secretlaunch.ErrNotInvoked)) {
		t.Fatalf("code = %d, out = %s", code, diagnostics.String())
	}
}

func TestSupervisorCLIFailsClosedWithoutProvider(t *testing.T) {
	manifestPath, trustPath, composePath := writeSupervisorFixtureFiles(t)
	var diagnostics bytes.Buffer
	code := run([]string{"--manifest", manifestPath, "--trust", trustPath, "--runtime", "docker-run", "--compose", composePath, "--invoke-docker"}, &diagnostics, nil, nil)
	if code != 1 || !strings.Contains(diagnostics.String(), string(secretlaunch.ErrNoProvider)) {
		t.Fatalf("code = %d, out = %s", code, diagnostics.String())
	}
}

func TestBoundedBufferRejectsUnboundedCommandOutput(t *testing.T) {
	var buffer boundedBuffer
	buffer.limit = 4
	if _, err := buffer.Write([]byte("abcd")); err != nil {
		t.Fatal(err)
	}
	written, err := buffer.Write([]byte("ef"))
	if err != errCommandOutputLimit || written != 0 {
		t.Fatalf("overflow write = (%d, %v)", written, err)
	}
	if got := buffer.String(); got != "abcd" {
		t.Fatalf("bounded output = %q", got)
	}
}

func loadFixturePolicy(t *testing.T, trustPath string) secretlaunch.TrustPolicy {
	t.Helper()
	trustBytes, err := os.ReadFile(trustPath)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := secretlaunch.LoadTrustDocument(trustBytes)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func TestManifestReloaderReturnsFreshVerifiedManifest(t *testing.T) {
	manifestPath, trustPath, _ := writeSupervisorFixtureFiles(t)
	policy := loadFixturePolicy(t, trustPath)
	reload := manifestReloader(manifestPath, policy, "docker-run", time.Now)
	manifest, err := reload(context.Background())
	if err != nil || manifest.RuntimeID != "docker-run" || manifest.Generation != 1 {
		t.Fatalf("reload = %+v, %v", manifest, err)
	}
}

func TestManifestReloaderRejectsUnusableFiles(t *testing.T) {
	manifestPath, trustPath, _ := writeSupervisorFixtureFiles(t)
	policy := loadFixturePolicy(t, trustPath)

	if _, err := manifestReloader(manifestPath, policy, "other-runtime", time.Now)(context.Background()); err == nil {
		t.Fatal("manifest for another runtime accepted")
	}
	late := func() time.Time { return time.Now().Add(time.Hour) }
	if _, err := manifestReloader(manifestPath, policy, "docker-run", late)(context.Background()); err == nil {
		t.Fatal("expired manifest accepted")
	}
	if _, err := manifestReloader(filepath.Join(t.TempDir(), "missing.json"), policy, "docker-run", time.Now)(context.Background()); err == nil {
		t.Fatal("missing manifest accepted")
	}
	if err := os.WriteFile(manifestPath, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := manifestReloader(manifestPath, policy, "docker-run", time.Now)(context.Background()); err == nil {
		t.Fatal("garbage manifest accepted")
	}
}

func TestReloadMonitorPrintsEachDistinctFailureOnce(t *testing.T) {
	var out bytes.Buffer
	monitor := newReloadMonitor(&out, time.Now, secretlaunch.Manifest{})
	first := &secretlaunch.LaunchError{Code: secretlaunch.ErrExpired}
	second := &secretlaunch.LaunchError{Code: secretlaunch.ErrBinding}
	for _, err := range []error{first, first, first, second, second, first} {
		monitor.Report(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 || !strings.Contains(lines[0], string(secretlaunch.ErrExpired)) ||
		!strings.Contains(lines[1], string(secretlaunch.ErrBinding)) || !strings.Contains(lines[2], string(secretlaunch.ErrExpired)) {
		t.Fatalf("reporter output = %q", out.String())
	}
}

// After a good reload the same failure is news again: a signer that flaps
// between working and failing must not stay silent after its first report.
func TestReloadMonitorReportsAFailureAgainAfterASuccessfulReload(t *testing.T) {
	var out bytes.Buffer
	base := monitorManifest(t, 1000)
	now := time.Unix(base.IssuedAt+10, 0)
	monitor := newReloadMonitor(&out, func() time.Time { return now }, base)
	failure := &secretlaunch.LaunchError{Code: secretlaunch.ErrExpired}
	succeed := monitor.Wrap(func(context.Context) (secretlaunch.Manifest, error) { return base, nil })

	monitor.Report(failure)
	monitor.Report(failure)
	if _, err := succeed(context.Background()); err != nil {
		t.Fatal(err)
	}
	monitor.Report(failure)
	if got := strings.Count(out.String(), string(secretlaunch.ErrExpired)); got != 2 {
		t.Fatalf("failure reported %d times, want 2:\n%s", got, out.String())
	}
}

// monitorManifest is a structurally valid manifest with a 600 second window
// starting at issuedAt, so AcceptRenewal can judge renewals of it.
func monitorManifest(t *testing.T, issuedAt int64) secretlaunch.Manifest {
	t.Helper()
	manifestPath, _, _ := writeSupervisorFixtureFiles(t)
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := secretlaunch.ParseSignedManifest(data)
	if err != nil {
		t.Fatal(err)
	}
	manifest := signed.Manifest
	manifest.IssuedAt, manifest.ExpiresAt = issuedAt, issuedAt+600
	return manifest
}

func TestReloadMonitorWarnsOnceWhenExpiryApproachesWithoutRenewal(t *testing.T) {
	var out bytes.Buffer
	base := monitorManifest(t, 1_000_000)
	var now time.Time
	monitor := newReloadMonitor(&out, func() time.Time { return now }, base)
	broken := monitor.Wrap(func(context.Context) (secretlaunch.Manifest, error) {
		return secretlaunch.Manifest{}, &secretlaunch.LaunchError{Code: secretlaunch.ErrInvalidInput}
	})

	now = time.Unix(base.IssuedAt+300, 0) // 300s left of 600s: plenty
	_, _ = broken(context.Background())
	if out.Len() != 0 {
		t.Fatalf("warned with half the window left: %q", out.String())
	}
	now = time.Unix(base.IssuedAt+401, 0) // 199s left: under a third
	for i := 0; i < 3; i++ {
		_, _ = broken(context.Background())
	}
	text := out.String()
	if strings.Count(text, "\n") != 1 || !strings.Contains(text, "no renewed manifest") ||
		!strings.Contains(text, time.Unix(base.ExpiresAt, 0).UTC().Format(time.RFC3339)) {
		t.Fatalf("warning = %q", text)
	}
}

func TestReloadMonitorStaysQuietWhenRenewalsArrive(t *testing.T) {
	var out bytes.Buffer
	base := monitorManifest(t, 1_000_000)
	var now time.Time
	monitor := newReloadMonitor(&out, func() time.Time { return now }, base)
	latest := base
	renewing := monitor.Wrap(func(context.Context) (secretlaunch.Manifest, error) { return latest, nil })

	for _, elapsed := range []int64{100, 300, 450, 700, 1000} {
		now = time.Unix(base.IssuedAt+elapsed, 0)
		latest = monitorManifest(t, now.Unix()-50)
		latest.ExpiresAt = now.Unix() + 550
		if _, err := renewing(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if out.Len() != 0 {
		t.Fatalf("warned although renewals arrived: %q", out.String())
	}

	// The next window runs out again without a successor: warn again, once.
	broken := monitor.Wrap(func(context.Context) (secretlaunch.Manifest, error) {
		return secretlaunch.Manifest{}, &secretlaunch.LaunchError{Code: secretlaunch.ErrInvalidInput}
	})
	now = time.Unix(latest.ExpiresAt-100, 0)
	_, _ = broken(context.Background())
	_, _ = broken(context.Background())
	if strings.Count(out.String(), "\n") != 1 {
		t.Fatalf("expected exactly one new warning, got %q", out.String())
	}
}

// A candidate the supervisor would refuse (other launch, earlier expiry) must
// not silence the warning for the window that is actually running.
func TestReloadMonitorIgnoresCandidatesTheSupervisorWouldRefuse(t *testing.T) {
	var out bytes.Buffer
	base := monitorManifest(t, 1_000_000)
	now := time.Unix(base.IssuedAt+450, 0)
	monitor := newReloadMonitor(&out, func() time.Time { return now }, base)
	other := base
	other.Generation = base.Generation + 1
	other.IssuedAt, other.ExpiresAt = now.Unix(), now.Unix()+600
	wrapped := monitor.Wrap(func(context.Context) (secretlaunch.Manifest, error) { return other, nil })
	_, _ = wrapped(context.Background())
	if !strings.Contains(out.String(), "no renewed manifest") {
		t.Fatalf("a refused candidate silenced the warning: %q", out.String())
	}
}

// The reloader must not rely on anything but the signature to trust a live
// manifest: each case below is unexpired and carries the same launch authority.
func TestManifestReloaderRejectsLiveManifestsWithoutAValidSignature(t *testing.T) {
	manifestPath, trustPath, _ := writeSupervisorFixtureFiles(t)
	policy := loadFixturePolicy(t, trustPath)
	original, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := secretlaunch.ParseSignedManifest(original)
	if err != nil {
		t.Fatal(err)
	}
	_, stranger, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signedBy := func(keyID string) []byte {
		data, err := secretlaunch.SignManifest(signed.Manifest, keyID, stranger, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	marshal := func(s secretlaunch.SignedManifest) []byte {
		data, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	flipped := signed
	raw, _ := base64.StdEncoding.DecodeString(signed.Signature)
	raw[0] ^= 0x01
	flipped.Signature = base64.StdEncoding.EncodeToString(raw)
	extended := signed
	extended.Manifest.ExpiresAt += 60 // a longer window under the old signature

	cases := map[string][]byte{
		"one flipped signature bit":           marshal(flipped),
		"signed by a key that is not trusted": signedBy("key-1"),
		"unknown key id":                      signedBy("key-unknown"),
		"window extended under old signature": marshal(extended),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(manifestPath, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := manifestReloader(manifestPath, policy, "docker-run", time.Now)(context.Background()); err == nil {
				t.Fatal("manifest without a valid signature was accepted")
			}
		})
	}
	if err := os.WriteFile(manifestPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := manifestReloader(manifestPath, policy, "docker-run", time.Now)(context.Background()); err != nil {
		t.Fatalf("control: the untouched manifest must still load: %v", err)
	}
}
