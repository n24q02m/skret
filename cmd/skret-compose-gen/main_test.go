package main

import (
	"bytes"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/n24q02m/skret/internal/secretlaunch"
)

const testNow = int64(1_758_500_000)

func digestOf(char string) string { return "sha256:" + strings.Repeat(char, 64) }

func writeCompose(t *testing.T, dir, body string) string {
	t.Helper()
	path := filepath.Join(dir, "docker-compose.yml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeKey(t *testing.T, dir, name string) (string, ed25519.PrivateKey) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(hex.EncodeToString(private)), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, private
}

const composeFixture = `
services:
  api:
    image: registry.example/api@sha256:` + "1111111111111111111111111111111111111111111111111111111111111111" + `
    user: "1000:1000"
    entrypoint: ["/app/api"]
    command: ["--serve", "--port", "8080"]
    environment:
      LOG_LEVEL: info
      DB_PASSWORD: ignored-literal
      API_TOKEN: ignored-literal
    labels:
      com.example.component: api
      com.skret.secret-launch.service: spoofed
    networks: [backend]
    depends_on: [db]
    healthcheck:
      test: ["CMD-SHELL", "curl -f http://localhost:8080/healthz"]
      interval: 15s
      timeout: 3s
      retries: 5
  db:
    image: registry.example/db@sha256:` + "2222222222222222222222222222222222222222222222222222222222222222" + `
    command: postgres -c log_min_messages=info
    environment:
      POSTGRES_PASSWORD: ignored-literal
      PGDATA: /var/lib/pg
    networks:
      backend: {}
`

func baseArgs(composePath, keyPath, out string) []string {
	return []string{
		"--compose", composePath,
		"--services", "api,db",
		"--runtime", "oci-vm-prod",
		"--out", out,
		"--key", "launch-key=" + keyPath,
		"--role", "prod",
		"--helper-digest", digestOf("a"),
		"--supervisor-digest", digestOf("b"),
		"--wrapper-digest", digestOf("c"),
		"--now", "1758500000",
		"--nonce", "test-nonce-0123456789",
		"--generation", "42",
		"--ttl", "10m",
	}
}

func generateArtifacts(t *testing.T, dir string, extra ...string) (string, ed25519.PrivateKey) {
	t.Helper()
	composePath := writeCompose(t, dir, composeFixture)
	keyPath, private := writeKey(t, dir, "signing.key")
	out := filepath.Join(dir, "out")
	args := append(baseArgs(composePath, keyPath, out), extra...)
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != 0 {
		t.Fatalf("run exit=%d stderr=%s", code, stderr.String())
	}
	return out, private
}

func loadArtifacts(t *testing.T, out string) (secretlaunch.Manifest, secretlaunch.RenderedModel, secretlaunch.TrustPolicy) {
	t.Helper()
	trustBytes, err := os.ReadFile(filepath.Join(out, "trust.json"))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := secretlaunch.LoadTrustDocument(trustBytes)
	if err != nil {
		t.Fatalf("trust document rejected by supervisor loader: %v", err)
	}
	signed, err := os.ReadFile(filepath.Join(out, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := secretlaunch.VerifySignedManifest(signed, policy, time.Unix(testNow, 0))
	if err != nil {
		t.Fatalf("signed manifest rejected by supervisor verify path: %v", err)
	}
	modelBytes, err := os.ReadFile(filepath.Join(out, "model.json"))
	if err != nil {
		t.Fatal(err)
	}
	model, err := secretlaunch.ParseRenderedModel(modelBytes)
	if err != nil {
		t.Fatalf("rendered model rejected by supervisor parser: %v", err)
	}
	return manifest, model, policy
}

func TestGenerateRoundTripThroughSupervisorVerifyPath(t *testing.T) {
	dir := t.TempDir()
	out, _ := generateArtifacts(t, dir)
	manifest, model, _ := loadArtifacts(t, out)

	if err := secretlaunch.ValidateManifestModel(manifest, model); err != nil {
		t.Fatalf("manifest/model binding rejected: %v", err)
	}
	if manifest.RuntimeID != "oci-vm-prod" || manifest.Role != "prod" || manifest.Generation != 42 {
		t.Fatalf("manifest identity = %#v", manifest)
	}
	if manifest.Digests.Compose != model.ComposeDigest {
		t.Fatalf("compose digest binding broken: %s vs %s", manifest.Digests.Compose, model.ComposeDigest)
	}
	if len(manifest.Services) != 2 || manifest.Services[0].Name != "api" || manifest.Services[1].Name != "db" {
		t.Fatalf("services not sorted by name: %#v", manifest.Services)
	}

	api := manifest.Services[0]
	if _, leaked := api.Environment["DB_PASSWORD"]; leaked {
		t.Fatal("secret-like environment entry leaked into manifest environment")
	}
	if _, leaked := api.Environment["API_TOKEN"]; leaked {
		t.Fatal("secret-like environment entry leaked into manifest environment")
	}
	if api.Environment["LOG_LEVEL"] != "info" {
		t.Fatalf("plain environment lost: %#v", api.Environment)
	}
	wantKeys := []secretlaunch.ManifestKey{
		{Name: "API_TOKEN", Version: "1", Env: "API_TOKEN"},
		{Name: "DB_PASSWORD", Version: "1", Env: "DB_PASSWORD"},
	}
	if len(api.Keys) != 2 || api.Keys[0] != wantKeys[0] || api.Keys[1] != wantKeys[1] {
		t.Fatalf("keys = %#v, want %#v", api.Keys, wantKeys)
	}
	if _, spoofed := api.Labels["com.skret.secret-launch.service"]; spoofed {
		t.Fatal("reserved ownership label survived generation")
	}
	if api.Restart != "no" || !api.OpenStdin {
		t.Fatal("restart/stdin policy not enforced")
	}
	if len(api.Dependencies) != 1 || api.Dependencies[0] != "db" {
		t.Fatalf("dependencies = %#v", api.Dependencies)
	}
	if api.Health.IntervalMS != 15_000 || api.Health.TimeoutMS != 3_000 || api.Health.Retries != 5 {
		t.Fatalf("health = %#v", api.Health)
	}
	if len(api.Health.Command) != 3 || api.Health.Command[0] != "/bin/sh" {
		t.Fatalf("CMD-SHELL health command = %#v", api.Health.Command)
	}
	if len(api.Argv) != 9 || api.Argv[0] != "/usr/local/bin/skret-secret-helper" || api.Argv[8] != "api" {
		t.Fatalf("helper argv = %#v", api.Argv)
	}
	if len(api.Child.Argv) != 4 || api.Child.Argv[0] != "/app/api" || api.Child.Argv[3] != "8080" {
		t.Fatalf("child argv = %#v", api.Child.Argv)
	}
	if api.Child.User != "1000:1000" {
		t.Fatalf("child user = %q", api.Child.User)
	}

	db := manifest.Services[1]
	if len(db.Child.Argv) != 3 || db.Child.Argv[0] != "/bin/sh" || db.Child.Argv[2] != "postgres -c log_min_messages=info" {
		t.Fatalf("scalar command wrap = %#v", db.Child.Argv)
	}
	if db.User != "root" {
		t.Fatalf("default user = %q", db.User)
	}
	if len(db.Keys) != 1 || db.Keys[0].Name != "POSTGRES_PASSWORD" {
		t.Fatalf("db keys = %#v", db.Keys)
	}
}

func TestGenerateIsDeterministic(t *testing.T) {
	dir := t.TempDir()
	composePath := writeCompose(t, dir, composeFixture)
	keyPath, _ := writeKey(t, dir, "signing.key")
	outA := filepath.Join(dir, "out-a")
	outB := filepath.Join(dir, "out-b")
	for _, out := range []string{outA, outB} {
		var stdout, stderr bytes.Buffer
		if code := run(baseArgs(composePath, keyPath, out), &stdout, &stderr); code != 0 {
			t.Fatalf("run exit=%d stderr=%s", code, stderr.String())
		}
	}
	for _, name := range []string{"manifest.json", "trust.json", "model.json"} {
		a, err := os.ReadFile(filepath.Join(outA, name))
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(filepath.Join(outB, name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(a, b) {
			t.Fatalf("%s not deterministic", name)
		}
	}
}
func TestGenerateMultipleKeysAndSignKeySelection(t *testing.T) {
	dir := t.TempDir()
	composePath := writeCompose(t, dir, composeFixture)
	keyA, privA := writeKey(t, dir, "a.key")
	keyB, privB := writeKey(t, dir, "b.key")
	pubC, _, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	args := append(baseArgs(composePath, keyA, out),
		"--key", "backup="+keyB,
		"--pubkey", "audit="+base64.StdEncoding.EncodeToString(pubC),
		"--sign-key", "backup",
		"--role", "staging",
		"--runtime-id", "oci-vm-staging",
		"--key-version", "EXTRA_KEY=7",
	)
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != 0 {
		t.Fatalf("run exit=%d stderr=%s", code, stderr.String())
	}
	manifest, _, policy := loadArtifacts(t, out)

	var signed secretlaunch.SignedManifest
	raw, err := os.ReadFile(filepath.Join(out, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &signed); err != nil {
		t.Fatal(err)
	}
	if signed.KeyID != "backup" {
		t.Fatalf("signed with %q, want backup", signed.KeyID)
	}
	if len(policy.AllowedSigningKeys) != 3 {
		t.Fatalf("trust keys = %d, want 3", len(policy.AllowedSigningKeys))
	}
	if !policy.AllowedRuntimeIDs["oci-vm-staging"] || !policy.AllowedRoles["staging"] {
		t.Fatal("extra runtime/role missing from trust")
	}
	if !policy.KeyVersions["EXTRA_KEY"]["7"] {
		t.Fatal("extra key version missing from trust")
	}
	// The signature must verify against the second key, not the first.
	canonical, err := manifest.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := base64.StdEncoding.DecodeString(signed.Signature)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(privB.Public().(ed25519.PublicKey), canonical, sig) {
		t.Fatal("signature does not verify under backup key")
	}
	if ed25519.Verify(privA.Public().(ed25519.PublicKey), canonical, sig) {
		t.Fatal("signature unexpectedly verifies under first key")
	}
}

func TestGenerateRejectsUnpinnedImage(t *testing.T) {
	dir := t.TempDir()
	composePath := writeCompose(t, dir, `
services:
  api:
    image: registry.example/api:latest
    command: ["/app/api"]
    environment:
      DB_PASSWORD: x
`)
	keyPath, _ := writeKey(t, dir, "k.key")
	var stderr bytes.Buffer
	args := []string{
		"--compose", composePath, "--services", "api", "--runtime", "oci-vm-prod",
		"--out", filepath.Join(dir, "out"), "--key", "k=" + keyPath, "--role", "prod",
		"--helper-digest", digestOf("a"), "--supervisor-digest", digestOf("b"),
		"--wrapper-digest", digestOf("c"), "--now", "1758500000",
		"--nonce", "test-nonce-0123456789", "--generation", "1",
	}
	if code := run(args, io.Discard, &stderr); code == 0 {
		t.Fatal("unpinned image accepted")
	}
	if !strings.Contains(stderr.String(), "digest-pinned") {
		t.Fatalf("stderr = %s", stderr.String())
	}
}

func TestGenerateRejectsInterpolation(t *testing.T) {
	dir := t.TempDir()
	composePath := writeCompose(t, dir, `
services:
  api:
    image: registry.example/api@sha256:`+"3333333333333333333333333333333333333333333333333333333333333333"+`
    command: ["/app/api"]
    environment:
      LOG_LEVEL: ${LOG_LEVEL}
      DB_PASSWORD: x
`)
	keyPath, _ := writeKey(t, dir, "k.key")
	var stderr bytes.Buffer
	args := []string{
		"--compose", composePath, "--services", "api", "--runtime", "oci-vm-prod",
		"--out", filepath.Join(dir, "out"), "--key", "k=" + keyPath, "--role", "prod",
		"--helper-digest", digestOf("a"), "--supervisor-digest", digestOf("b"),
		"--wrapper-digest", digestOf("c"), "--now", "1758500000",
		"--nonce", "test-nonce-0123456789", "--generation", "1",
	}
	if code := run(args, io.Discard, &stderr); code == 0 {
		t.Fatal("unresolved interpolation accepted")
	}
	if !strings.Contains(stderr.String(), "interpolation") {
		t.Fatalf("stderr = %s", stderr.String())
	}
}

func TestGenerateRejectsServiceWithoutKeys(t *testing.T) {
	dir := t.TempDir()
	composePath := writeCompose(t, dir, `
services:
  api:
    image: registry.example/api@sha256:`+"4444444444444444444444444444444444444444444444444444444444444444"+`
    command: ["/app/api"]
    environment:
      LOG_LEVEL: info
`)
	keyPath, _ := writeKey(t, dir, "k.key")
	var stderr bytes.Buffer
	args := []string{
		"--compose", composePath, "--services", "api", "--runtime", "oci-vm-prod",
		"--out", filepath.Join(dir, "out"), "--key", "k=" + keyPath, "--role", "prod",
		"--helper-digest", digestOf("a"), "--supervisor-digest", digestOf("b"),
		"--wrapper-digest", digestOf("c"), "--now", "1758500000",
		"--nonce", "test-nonce-0123456789", "--generation", "1",
	}
	if code := run(args, io.Discard, &stderr); code == 0 {
		t.Fatal("service without secret keys accepted")
	}
	if !strings.Contains(stderr.String(), "no secret keys") {
		t.Fatalf("stderr = %s", stderr.String())
	}
}

func TestExplicitSecretMapping(t *testing.T) {
	dir := t.TempDir()
	composePath := writeCompose(t, dir, `
services:
  api:
    image: registry.example/api@sha256:`+"5555555555555555555555555555555555555555555555555555555555555555"+`
    command: ["/app/api"]
    environment:
      LOG_LEVEL: info
`)
	keyPath, _ := writeKey(t, dir, "k.key")
	out := filepath.Join(dir, "out")
	args := []string{
		"--compose", composePath, "--services", "api", "--runtime", "oci-vm-prod",
		"--out", out, "--key", "k=" + keyPath, "--role", "prod",
		"--helper-digest", digestOf("a"), "--supervisor-digest", digestOf("b"),
		"--wrapper-digest", digestOf("c"), "--now", "1758500000",
		"--nonce", "test-nonce-0123456789", "--generation", "1",
		"--secret", "api=APP_DATABASE_URL=/oci-vm-prod/prod/db-url:3",
	}
	var stderr bytes.Buffer
	if code := run(args, io.Discard, &stderr); code != 0 {
		t.Fatalf("run exit=%d stderr=%s", code, stderr.String())
	}
	manifest, _, _ := loadArtifacts(t, out)
	keys := manifest.Services[0].Keys
	if len(keys) != 1 || keys[0].Name != "/oci-vm-prod/prod/db-url" || keys[0].Version != "3" || keys[0].Env != "APP_DATABASE_URL" {
		t.Fatalf("keys = %#v", keys)
	}
}
