package main

import (
	"bytes"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/n24q02m/skret/internal/secretlaunch"
)

type signerFixture struct {
	dir       string
	template  string
	trust     string
	key       string
	model     string
	out       string
	private   ed25519.PrivateKey
	manifest  secretlaunch.Manifest
	policy    secretlaunch.TrustPolicy
	issuedAt  time.Time
	keyHex    string
	modelDoc  secretlaunch.RenderedModel
	trustDoc  secretlaunch.TrustDocument
	signedRaw []byte
}

func newSignerFixture(t *testing.T) *signerFixture {
	t.Helper()
	dir := t.TempDir()
	public, private, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issued := time.Now().Add(-2 * time.Minute).Truncate(time.Second)
	environment := map[string]string{"LOG_LEVEL": "info"}
	child := secretlaunch.ChildSpec{Argv: []string{"/bin/echo", "ok"}, User: "current", Environment: environment}
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
		Version: secretlaunch.ManifestVersion, RuntimeID: "docker-run", Role: "prod-api", Generation: 4,
		IssuedAt: issued.Unix(), ExpiresAt: issued.Add(10 * time.Minute).Unix(), Nonce: "nonce-1234567890",
		Services: []secretlaunch.ServiceAuthority{authority},
		Digests: secretlaunch.ArtifactDigests{
			Helper: "sha256:" + strings.Repeat("1", 64), Supervisor: "sha256:" + strings.Repeat("2", 64),
			Compose: modelDoc.ComposeDigest,
		},
	}
	signed, err := secretlaunch.SignManifest(manifest, "key-1", private, issued)
	if err != nil {
		t.Fatal(err)
	}
	trustDoc := secretlaunch.TrustDocument{
		Keys:        map[string]string{"key-1": base64.StdEncoding.EncodeToString(public)},
		Versions:    []string{secretlaunch.ManifestVersion},
		RuntimeIDs:  []string{manifest.RuntimeID},
		Roles:       []string{manifest.Role},
		KeyVersions: map[string]map[string]bool{"APP_TOKEN": {"1": true}},
	}
	policy, err := secretlaunch.LoadTrustDocument(mustJSON(t, trustDoc))
	if err != nil {
		t.Fatal(err)
	}
	f := &signerFixture{
		dir: dir, template: filepath.Join(dir, "template.json"), trust: filepath.Join(dir, "trust.json"),
		key: filepath.Join(dir, "signing.key"), model: filepath.Join(dir, "model.json"), out: filepath.Join(dir, "out", "manifest.json"),
		private: private, manifest: manifest, policy: policy, issuedAt: issued, keyHex: hex.EncodeToString(private),
		modelDoc: modelDoc, trustDoc: trustDoc, signedRaw: signed,
	}
	writeFile(t, f.template, signed, 0o644)
	writeFile(t, f.trust, mustJSON(t, trustDoc), 0o644)
	writeFile(t, f.key, []byte(f.keyHex+"\n"), 0o600)
	writeFile(t, f.model, mustJSON(t, modelDoc), 0o644)
	if err := os.Mkdir(filepath.Dir(f.out), 0o755); err != nil {
		t.Fatal(err)
	}
	return f
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func writeFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
}

func (f *signerFixture) args(extra ...string) []string {
	args := []string{
		"--template", f.template, "--trust", f.trust, "--key", f.key, "--model", f.model, "--out", f.out,
		"--max-age", "168h",
	}
	return append(args, extra...)
}

func TestSignerRenewsTemplateAtomically(t *testing.T) {
	f := newSignerFixture(t)
	now := f.issuedAt.Add(5 * time.Minute)
	var diagnostics bytes.Buffer
	if code := run(f.args(), &diagnostics, func() time.Time { return now }); code != 0 {
		t.Fatalf("code = %d, diagnostics = %s", code, diagnostics.String())
	}
	data, err := os.ReadFile(f.out)
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := secretlaunch.VerifySignedManifest(data, f.policy, now)
	if err != nil {
		t.Fatalf("output does not verify: %v", err)
	}
	if err := secretlaunch.AcceptRenewal(f.manifest, renewed, now); err != nil {
		t.Fatalf("output is not an acceptable renewal: %v", err)
	}
	if renewed.ExpiresAt != now.Add(10*time.Minute).Unix() {
		t.Fatalf("default ttl not applied: expires_at = %d", renewed.ExpiresAt)
	}
	text := diagnostics.String()
	if !strings.Contains(text, "docker-run") || !strings.Contains(text, "key-1") {
		t.Fatalf("diagnostics lack renewal summary: %q", text)
	}
	if strings.Contains(text, f.keyHex) || strings.Contains(text, base64.StdEncoding.EncodeToString(f.private)) {
		t.Fatal("diagnostics leak key material")
	}
	entries, _ := os.ReadDir(filepath.Dir(f.out))
	if len(entries) != 1 {
		t.Fatalf("temporary files left behind: %v", entries)
	}
}

func TestSignerHonoursExplicitTTL(t *testing.T) {
	f := newSignerFixture(t)
	now := f.issuedAt.Add(time.Minute)
	if code := run(f.args("--ttl", "3m"), &bytes.Buffer{}, func() time.Time { return now }); code != 0 {
		t.Fatalf("code = %d", code)
	}
	data, _ := os.ReadFile(f.out)
	renewed, err := secretlaunch.VerifySignedManifest(data, f.policy, now)
	if err != nil || renewed.ExpiresAt != now.Add(3*time.Minute).Unix() {
		t.Fatalf("renewed = %+v, %v", renewed, err)
	}
}

func TestSignerFailsWithoutTouchingExistingOutput(t *testing.T) {
	now := func(f *signerFixture) func() time.Time {
		return func() time.Time { return f.issuedAt.Add(time.Minute) }
	}
	cases := map[string]struct {
		mutate func(t *testing.T, f *signerFixture) []string
		code   int
	}{
		"max age exceeded": {func(t *testing.T, f *signerFixture) []string { return f.args("--max-age", "30s") }, 1},
		"ttl over cap":     {func(t *testing.T, f *signerFixture) []string { return f.args("--ttl", "16m") }, 1},
		"missing max age": {func(t *testing.T, f *signerFixture) []string {
			return []string{"--template", f.template, "--trust", f.trust, "--key", f.key, "--model", f.model, "--out", f.out}
		}, 2},
		"missing template flag": {func(t *testing.T, f *signerFixture) []string {
			return []string{"--trust", f.trust, "--key", f.key, "--model", f.model, "--out", f.out, "--max-age", "1h"}
		}, 2},
		"unknown flag":   {func(t *testing.T, f *signerFixture) []string { return f.args("--bogus") }, 2},
		"positional arg": {func(t *testing.T, f *signerFixture) []string { return f.args("extra") }, 2},
		"bad duration":   {func(t *testing.T, f *signerFixture) []string { return f.args("--ttl", "soon") }, 2},
		"tampered template": {func(t *testing.T, f *signerFixture) []string {
			writeFile(t, f.template, bytes.Replace(f.signedRaw, []byte(`"generation":4`), []byte(`"generation":5`), 1), 0o644)
			return f.args()
		}, 1},
		"foreign key": {func(t *testing.T, f *signerFixture) []string {
			_, other, _ := ed25519.GenerateKey(cryptorand.Reader)
			writeFile(t, f.key, []byte(hex.EncodeToString(other)), 0o600)
			return f.args()
		}, 1},
		"unreadable key": {func(t *testing.T, f *signerFixture) []string {
			writeFile(t, f.key, []byte("not a key"), 0o600)
			return f.args()
		}, 1},
		"model digest mismatch": {func(t *testing.T, f *signerFixture) []string {
			other := f.modelDoc
			other.Services = append([]secretlaunch.ServiceSpec(nil), f.modelDoc.Services...)
			other.Services[0].Image = "registry.example/api@sha256:" + strings.Repeat("9", 64)
			other.ComposeDigest, _ = secretlaunch.ModelDigest(other)
			writeFile(t, f.model, mustJSON(t, other), 0o644)
			return f.args()
		}, 1},
		"garbage model": {func(t *testing.T, f *signerFixture) []string {
			writeFile(t, f.model, []byte("{"), 0o644)
			return f.args()
		}, 1},
		"missing template file": {func(t *testing.T, f *signerFixture) []string {
			return append(f.args(), "--template", filepath.Join(f.dir, "nope.json"))
		}, 1},
		"garbage trust document": {func(t *testing.T, f *signerFixture) []string {
			writeFile(t, f.trust, []byte("{"), 0o644)
			return f.args()
		}, 1},
		"missing model file": {func(t *testing.T, f *signerFixture) []string {
			return append(f.args(), "--model", filepath.Join(f.dir, "nope.json"))
		}, 1},
		"missing trust": {func(t *testing.T, f *signerFixture) []string {
			return append(f.args(), "--trust", filepath.Join(f.dir, "nope.json"))
		}, 1},
		"output directory missing": {func(t *testing.T, f *signerFixture) []string {
			return append(f.args(), "--out", filepath.Join(f.dir, "absent", "manifest.json"))
		}, 1},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newSignerFixture(t)
			writeFile(t, f.out, []byte("previous"), 0o644)
			args := tc.mutate(t, f)
			var diagnostics bytes.Buffer
			if code := run(args, &diagnostics, now(f)); code != tc.code {
				t.Fatalf("code = %d, want %d; diagnostics = %s", code, tc.code, diagnostics.String())
			}
			if strings.Contains(diagnostics.String(), f.keyHex) {
				t.Fatal("diagnostics leak key material")
			}
			if got, _ := os.ReadFile(f.out); string(got) != "previous" {
				t.Fatalf("existing output was modified: %q", got)
			}
		})
	}
}

// A signer pointed at its own output would measure --max-age from the issued_at
// it wrote last time, so every run would reset the clock and renewal would
// never stop. The template must therefore never be the output file, nor any
// alias of it.
func TestSignerRefusesToRenewItsOwnOutput(t *testing.T) {
	cases := map[string]func(t *testing.T, f *signerFixture) []string{
		"same path": func(t *testing.T, f *signerFixture) []string {
			writeFile(t, f.out, f.signedRaw, 0o644)
			return f.args("--template", f.out)
		},
		"output is a symlink to the template": func(t *testing.T, f *signerFixture) []string {
			if err := os.Symlink(f.template, f.out); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			return f.args()
		},
		"output is a hard link to the template": func(t *testing.T, f *signerFixture) []string {
			if err := os.Link(f.template, f.out); err != nil {
				t.Skipf("hard links unavailable: %v", err)
			}
			return f.args()
		},
		"same file through a different spelling": func(t *testing.T, f *signerFixture) []string {
			writeFile(t, f.out, f.signedRaw, 0o644)
			return f.args("--template", filepath.Join(filepath.Dir(f.out), ".", "manifest.json"))
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			f := newSignerFixture(t)
			args := setup(t, f)
			before, err := os.ReadFile(f.out)
			if err != nil {
				t.Fatal(err)
			}
			var diagnostics bytes.Buffer
			now := f.issuedAt.Add(5 * time.Minute)
			if code := run(args, &diagnostics, func() time.Time { return now }); code != 1 {
				t.Fatalf("code = %d, want 1; diagnostics = %s", code, diagnostics.String())
			}
			after, err := os.ReadFile(f.out)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("output was rewritten: %v", err)
			}
			if got, _ := os.ReadFile(f.template); !bytes.Equal(got, f.signedRaw) {
				t.Fatal("template was rewritten")
			}
		})
	}
}

// Renewal must stay bounded by the age of the template however many times the
// signer runs and however fresh its output looks.
func TestSignerMaxAgeBoundsRepeatedRenewals(t *testing.T) {
	f := newSignerFixture(t)
	args := f.args("--max-age", "1h")
	for _, elapsed := range []time.Duration{5 * time.Minute, 25 * time.Minute, 55 * time.Minute} {
		now := f.issuedAt.Add(elapsed)
		if code := run(args, &bytes.Buffer{}, func() time.Time { return now }); code != 0 {
			t.Fatalf("renewal at +%s rejected: %d", elapsed, code)
		}
	}
	late := f.issuedAt.Add(4 * time.Hour)
	if code := run(args, &bytes.Buffer{}, func() time.Time { return late }); code != 1 {
		t.Fatalf("renewal at +4h with --max-age 1h = %d, want 1", code)
	}
}

func TestSignerRejectsMaxAgeOverCap(t *testing.T) {
	f := newSignerFixture(t)
	over := (secretlaunch.MaxRenewalAge + time.Hour).String()
	if code := run(f.args("--max-age", over), &bytes.Buffer{}, func() time.Time { return f.issuedAt }); code != 2 {
		t.Fatalf("--max-age %s = %d, want 2", over, code)
	}
}

func TestSignerRejectsBroadSigningKeyPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not meaningful on Windows")
	}
	f := newSignerFixture(t)
	writeFile(t, f.out, []byte("previous"), 0o644)
	if err := os.Chmod(f.key, 0o644); err != nil {
		t.Fatal(err)
	}
	var diagnostics bytes.Buffer
	if code := run(f.args(), &diagnostics, func() time.Time { return f.issuedAt.Add(time.Minute) }); code != 1 {
		t.Fatalf("world-readable key accepted: code = %d, diagnostics = %s", code, diagnostics.String())
	}
	if got, _ := os.ReadFile(f.out); string(got) != "previous" {
		t.Fatalf("output was modified: %q", got)
	}
	if strings.Contains(diagnostics.String(), f.keyHex) {
		t.Fatal("diagnostics leak key material")
	}
}
