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
	"io"
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
		Health:        secretlaunch.HealthSpec{Command: []string{"/bin/true"}, IntervalMS: 10, TimeoutMS: 10, Retries: 1},
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
	if err := os.WriteFile(manifestPath, signedBytes, 0600); err != nil {
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
	if err := os.WriteFile(trustPath, trustBytes, 0600); err != nil {
		t.Fatal(err)
	}
	modelBytes, err := json.Marshal(modelDoc)
	if err != nil {
		t.Fatal(err)
	}
	composePath := filepath.Join(dir, "compose.json")
	if err := os.WriteFile(composePath, modelBytes, 0600); err != nil {
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

type fakeSupervisorRuntime struct {
	reconciled bool
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

func (f *fakeSupervisorRuntime) Render(context.Context, secretlaunch.RenderedModel) (secretlaunch.RenderedModel, error) {
	f.reconciled = true
	return secretlaunch.RenderedModel{}, nil
}

func (f *fakeSupervisorRuntime) List(context.Context, map[string]string) ([]secretlaunch.Container, error) {
	return nil, nil
}

func (f *fakeSupervisorRuntime) Inspect(context.Context, string) (secretlaunch.ContainerState, error) {
	return secretlaunch.ContainerState{}, nil
}

func (f *fakeSupervisorRuntime) Create(context.Context, secretlaunch.ServiceSpec, map[string]string) (secretlaunch.Container, error) {
	return secretlaunch.Container{}, nil
}

func (f *fakeSupervisorRuntime) Attach(context.Context, string) (io.ReadWriteCloser, error) {
	return nil, nil
}
func (f *fakeSupervisorRuntime) Start(context.Context, string) error { return nil }

func (f *fakeSupervisorRuntime) Kill(context.Context, string) error { return nil }

func (f *fakeSupervisorRuntime) Remove(context.Context, string, bool) error { return nil }
