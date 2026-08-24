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

func writeTempFiles(t *testing.T) (string, string) {
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
	authority := secretlaunch.ServiceAuthority{
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
		Keys:          []secretlaunch.ManifestKey{{Name: "APP_TOKEN", Version: "1", Env: "APP_TOKEN"}},
		WrapperDigest: "sha256:" + strings.Repeat("3", 64),
		Child: secretlaunch.ChildSpec{
			Argv: []string{"/bin/echo", "ok"}, User: "current", Environment: environment,
		},
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
			Helper:     fmt.Sprintf("sha256:%x", executableSHA[:]),
			Supervisor: "sha256:" + strings.Repeat("2", 64),
			Compose:    "sha256:" + strings.Repeat("4", 64),
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
	return manifestPath, trustPath
}

func TestHelperCLIRejectsMissingArgumentsAndFailClosed(t *testing.T) {
	var diagnostics bytes.Buffer
	code := run([]string{"--manifest=only-this"}, bytes.NewReader(nil), &bytes.Buffer{}, &diagnostics)
	if code != 2 {
		t.Fatalf("exit code = %d, output = %s", code, diagnostics.String())
	}
}

func TestHelperCLIRejectsTamperedManifest(t *testing.T) {
	manifestPath, trustPath := writeTempFiles(t)
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-3] ^= 1
	if err := os.WriteFile(manifestPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	var diagnostics bytes.Buffer
	code := run([]string{"--manifest", manifestPath, "--trust", trustPath, "--runtime", "docker-run", "--service", "api"}, bytes.NewReader(nil), &bytes.Buffer{}, &diagnostics)
	if code != 1 || strings.Contains(diagnostics.String(), "synthetic-sentinel") {
		t.Fatalf("code = %d, out = %s", code, diagnostics.String())
	}
}

type fakeRunner struct{}

func (fakeRunner) Run(context.Context, string, ...string) ([]byte, []byte, error) {
	return []byte("ok"), nil, nil
}
