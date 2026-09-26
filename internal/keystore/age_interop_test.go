package keystore

// External interop proof (SK-ENC acceptance): files skret seals in the
// standard age format MUST decrypt with the standalone age CLI, and files
// the standalone age CLI seals MUST decrypt with skret.
//
// The age binary is built OUTSIDE skret from the reference implementation
// module (filippo.io/age/cmd/age — the same code the upstream age release
// binaries ship) into a throwaway directory, then exercised as a black-box
// process: `age -d -i key.txt secrets.encrypted.yaml`. If the toolchain
// cannot produce the binary, the test skips with that reason and format
// conformance remains proven by the reference library round-trips in
// keystore_test.go (Skrypt/X25519 arms via filippo.io/age itself).
// The passphrase (scrypt) arm is proven by reference-lib round-trip only:
// the age CLI reads passphrases from a terminal, which CI does not have.

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	// The external-CLI interop tests below build filippo.io/age/cmd/age as
	// a subprocess, which pulls the agessh package and this module. A blank
	// import keeps it in go.mod/go.sum (go mod tidy would otherwise prune
	// the sums the subprocess build needs in -mod=readonly mode).
	_ "filippo.io/edwards25519"

	"filippo.io/age"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// buildAgeCLI builds the reference age CLI + age-keygen from the module
// dependency (no network once the module cache is warm) and returns their
// paths. Skips when the toolchain cannot provide them.
func buildAgeCLI(t *testing.T) (string, string) {
	t.Helper()
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skipf("go toolchain not in PATH; cannot build the reference age CLI (%v)", err)
	}
	dir := t.TempDir()
	ageBin := filepath.Join(dir, "age")
	keygenBin := filepath.Join(dir, "age-keygen")
	if runtime.GOOS == "windows" {
		ageBin += ".exe"
		keygenBin += ".exe"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	for _, target := range []struct{ pkg, out string }{
		{"filippo.io/age/cmd/age", ageBin},
		{"filippo.io/age/cmd/age-keygen", keygenBin},
	} {
		cmd := exec.CommandContext(ctx, goBin, "build", "-o", target.out, target.pkg)
		if out, berr := cmd.CombinedOutput(); berr != nil {
			t.Skipf("building %s failed; age-CLI interop test skipped (format still proven via the reference lib): %v\n%s",
				target.pkg, berr, out)
		}
	}
	return ageBin, keygenBin
}

// runAge runs an age CLI command and returns stdout, failing on error.
func runAge(t *testing.T, bin string, stdin []byte, args ...string) string {
	t.Helper()
	var stdout, stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdin = bytes.NewReader(stdin)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s %v failed: %v\nstderr: %s", filepath.Base(bin), args, err, stderr.String())
	}
	return stdout.String()
}

// publicKeyOf extracts the bech32 public key from age-keygen output.
func publicKeyOf(t *testing.T, keygenOutput string) string {
	t.Helper()
	var pubkey string
	for _, line := range strings.Split(keygenOutput, "\n") {
		if after, found := strings.CutPrefix(line, "# public key: "); found {
			pubkey = strings.TrimSpace(after)
		}
	}
	require.NotEmpty(t, pubkey, "age-keygen output must contain the public key comment")
	require.True(t, strings.HasPrefix(pubkey, "age1"), "age public keys are bech32 with the age1 HRP")
	return pubkey
}

// interopPayload is the encrypted payload shape used by the interop tests:
// secrets plus per-key metadata (expiry), exactly what skret seals.
type interopPayload struct {
	Version string            `yaml:"version"`
	Secrets map[string]string `yaml:"secrets"`
	Meta    map[string]string `yaml:"meta,omitempty"`
}

func TestAgeInteropExternalCLIDecryptsSkretSealed(t *testing.T) {
	ageBin, _ := buildAgeCLI(t)

	// skret generates the identity and seals the file (the `keys init` /
	// provider save path).
	identity, err := GenerateIdentity()
	require.NoError(t, err)
	secrets := map[string]string{
		"DATABASE_URL": "postgres://dev:dev@localhost/db",
		"API_TOKEN":    "kW9xP2vQ8mZ5#J7&R4tU6yB3nL0cD1f",
	}
	meta := map[string]string{"API_TOKEN": "2026-10-19T00:00:00Z"}
	sealed, err := SealWithMeta(secrets, meta, identity)
	require.NoError(t, err)

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.txt")
	require.NoError(t, os.WriteFile(keyPath, []byte(identity+"\n"), 0o600))
	filePath := filepath.Join(dir, ".secrets.dev.yaml")
	require.NoError(t, os.WriteFile(filePath, sealed, 0o600))
	require.True(t, Detect(sealed), "skret-sealed file must carry the age magic header")

	// The external age CLI decrypts it: `age -d -i key.txt <file>`.
	out := runAge(t, ageBin, nil, "-d", "-i", keyPath, filePath)
	var got interopPayload
	require.NoError(t, yaml.Unmarshal([]byte(out), &got))
	assert.Equal(t, "1", got.Version)
	assert.Equal(t, secrets, got.Secrets, "external age decrypt must return every value byte-exact")
	assert.Equal(t, meta, got.Meta, "per-key metadata must survive the round trip")
}

func TestAgeInteropSkretSealsToExternalKeygenKey(t *testing.T) {
	ageBin, keygenBin := buildAgeCLI(t)

	// age-keygen (external tool) mints the keypair; the file carries the
	// private key plus the "# public key:" comment.
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.txt")
	runAge(t, keygenBin, nil, "-o", keyPath)
	keyFile, err := os.ReadFile(keyPath)
	require.NoError(t, err)
	pubkey := publicKeyOf(t, string(keyFile))

	secrets := map[string]string{"KEY": "external-keypair-value"}
	sealed, err := SealWithMeta(secrets, nil, pubkey)
	require.NoError(t, err)
	require.Equal(t, "X25519", StanzaKind(sealed))

	filePath := filepath.Join(dir, "secrets.yaml")
	require.NoError(t, os.WriteFile(filePath, sealed, 0o600))

	out := runAge(t, ageBin, nil, "-d", "-i", keyPath, filePath)
	var got interopPayload
	require.NoError(t, yaml.Unmarshal([]byte(out), &got))
	assert.Equal(t, secrets, got.Secrets)
}

func TestAgeInteropSkretDecryptsCLISealedFile(t *testing.T) {
	ageBin, keygenBin := buildAgeCLI(t)

	// The external CLI seals a plaintext payload to its own keypair.
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.txt")
	runAge(t, keygenBin, nil, "-o", keyPath)
	keyFile, err := os.ReadFile(keyPath)
	require.NoError(t, err)
	pubkey := publicKeyOf(t, string(keyFile))

	plaintext := "version: \"1\"\nsecrets:\n  FROM_CLI: cli-sealed-value\n"
	filePath := filepath.Join(dir, "cli-sealed.yaml")
	runAge(t, ageBin, []byte(plaintext), "-e", "-r", pubkey, "-o", filePath)

	raw, err := os.ReadFile(filePath)
	require.NoError(t, err)
	require.True(t, Detect(raw), "CLI-sealed file must carry the age magic header")

	identity := privateKeyOf(t, string(keyFile))
	secrets, err := Open(raw, identity)
	require.NoError(t, err, "skret must decrypt a file the standalone age CLI sealed")
	assert.Equal(t, map[string]string{"FROM_CLI": "cli-sealed-value"}, secrets)
}

// privateKeyOf extracts the AGE-SECRET-KEY line from age-keygen output.
func privateKeyOf(t *testing.T, keygenOutput string) string {
	t.Helper()
	for _, line := range strings.Split(keygenOutput, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "AGE-SECRET-KEY-") {
			return line
		}
	}
	t.Fatal("age-keygen output must contain the private key line")
	return ""
}

// decryptPayloadForTest decrypts raw with the reference library and returns
// the plaintext payload bytes (what external `age -d` would print).
func decryptPayloadForTest(t *testing.T, raw []byte, material string) string {
	t.Helper()
	id, err := identityFor(material)
	require.NoError(t, err)
	r, err := age.Decrypt(bytes.NewReader(raw), id)
	require.NoError(t, err)
	plain, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(plain)
}

func TestPassphraseArmScryptRoundTrip(t *testing.T) {
	// The passphrase arm uses age scrypt recipients (spec 5.3.4). The age
	// CLI derives the same recipient from a terminal passphrase; CI has no
	// TTY, so format conformance is proven against the reference
	// implementation's ScryptIdentity/ScryptRecipient (the same code path
	// `age -p` uses).
	passphrase := "correct horse battery staple"
	secrets := map[string]string{"K": "passphrase-arm-value"}

	raw, err := Seal(secrets, passphrase)
	require.NoError(t, err)
	require.True(t, Detect(raw))
	require.Equal(t, "scrypt", StanzaKind(raw), "passphrase material must produce a scrypt stanza")

	got, err := Open(raw, passphrase)
	require.NoError(t, err)
	assert.Equal(t, secrets, got)

	_, err = Open(raw, "wrong-passphrase")
	require.Error(t, err)
}
