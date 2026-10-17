package secretlaunch

import (
	"bytes"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func writeKeyFile(t *testing.T, content []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "signing.key")
	if err := os.WriteFile(path, content, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadSigningKeyFileAcceptsSupportedEncodings(t *testing.T) {
	_, private, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	seed := private.Seed()
	cases := map[string][]byte{
		"hex private":    []byte(hex.EncodeToString(private) + "\n"),
		"base64 private": []byte(base64.StdEncoding.EncodeToString(private)),
		"hex seed":       []byte(hex.EncodeToString(seed)),
		"base64 seed":    []byte(base64.StdEncoding.EncodeToString(seed) + "\n"),
		"raw private":    private,
		"raw seed":       seed,
	}
	for name, content := range cases {
		got, err := ReadSigningKeyFile(writeKeyFile(t, content, 0o600))
		if err != nil || !bytes.Equal(got, private) {
			t.Errorf("%s: err = %v, key matches = %v", name, err, bytes.Equal(got, private))
		}
	}
}

func TestReadSigningKeyFileRejectsUnusableFiles(t *testing.T) {
	if _, err := ReadSigningKeyFile(filepath.Join(t.TempDir(), "missing.key")); errorCode(err) != ErrInvalidInput {
		t.Fatalf("missing file err = %v", err)
	}
	for name, content := range map[string][]byte{
		"empty":        {},
		"short":        []byte("abcd"),
		"wrong length": bytes.Repeat([]byte{1}, 40),
	} {
		if _, err := ReadSigningKeyFile(writeKeyFile(t, content, 0o600)); errorCode(err) != ErrInvalidInput {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestReadSigningKeyFileRejectsBroadPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not meaningful on Windows")
	}
	_, private, _ := ed25519.GenerateKey(cryptorand.Reader)
	path := writeKeyFile(t, []byte(hex.EncodeToString(private)), 0o600)
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSigningKeyFile(path); errorCode(err) != ErrInvalidInput {
		t.Fatalf("group-readable key accepted: %v", err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSigningKeyFile(path); err != nil {
		t.Fatalf("0400 key rejected: %v", err)
	}
}

func TestReadSigningKeyFileRejectsSymlink(t *testing.T) {
	_, private, _ := ed25519.GenerateKey(cryptorand.Reader)
	target := writeKeyFile(t, []byte(hex.EncodeToString(private)), 0o600)
	link := filepath.Join(t.TempDir(), "link.key")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := ReadSigningKeyFile(link); errorCode(err) != ErrInvalidInput {
		t.Fatalf("symlinked key accepted: %v", err)
	}
}

func TestWriteFileAtomicReplacesWithoutLeavingTemporaries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(path, []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "new" {
		t.Fatalf("content = %q, %v", got, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("directory entries = %v, %v", entries, err)
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0o644 {
			t.Fatalf("mode = %v", info.Mode().Perm())
		}
	}
}

func TestWriteFileAtomicFailsWithoutDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "manifest.json")
	if err := WriteFileAtomic(path, []byte("x"), 0o644); err == nil {
		t.Fatal("write into a missing directory succeeded")
	}
	if err := WriteFileAtomic("", []byte("x"), 0o644); err == nil {
		t.Fatal("empty path accepted")
	}
}

func TestWriteFileAtomicKeepsOldFileWhenTargetIsDirectory(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(target, []byte("x"), 0o644); err == nil {
		t.Fatal("replacing a directory succeeded")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temporary file left behind: %v", entries)
	}
}

func TestReadSigningKeyFileRejectsOversizedFileAndDirectory(t *testing.T) {
	if _, err := ReadSigningKeyFile(writeKeyFile(t, bytes.Repeat([]byte{'a'}, maxSigningKeyFileBytes+1), 0o600)); err == nil {
		t.Fatal("oversized key file accepted")
	}
	if _, err := ReadSigningKeyFile(t.TempDir()); errorCode(err) != ErrInvalidInput {
		t.Fatalf("directory accepted: %v", err)
	}
}
