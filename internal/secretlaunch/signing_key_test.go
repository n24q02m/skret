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

func TestReadSigningKeyFileReportsUnreadableFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not meaningful on Windows")
	}
	path := writeKeyFile(t, []byte("synthetic"), 0o600)
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	if f, err := os.Open(path); err == nil {
		_ = f.Close()
		t.Skip("running with privileges that bypass file modes")
	}
	if _, err := ReadSigningKeyFile(path); err == nil {
		t.Fatal("unreadable key file accepted")
	}
}

// The permission check must look at the file that is actually open, not at what
// the path pointed to a moment earlier: a path swapped between the Lstat and
// the open would otherwise carry an unchecked file into the key parser.
func TestCheckSigningKeyHandleJudgesTheOpenFile(t *testing.T) {
	_, private, _ := ed25519.GenerateKey(cryptorand.Reader)
	good := writeKeyFile(t, []byte(hex.EncodeToString(private)), 0o600)
	other := writeKeyFile(t, []byte(hex.EncodeToString(private)), 0o600)

	goodInfo, err := os.Lstat(good)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := os.Open(other)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	if err := checkSigningKeyHandle(handle, goodInfo); errorCode(err) != ErrInvalidInput {
		t.Fatalf("a handle for a different file than the one inspected was accepted: %v", err)
	}
	otherInfo, _ := os.Lstat(other)
	if err := checkSigningKeyHandle(handle, otherInfo); err != nil {
		t.Fatalf("matching handle rejected: %v", err)
	}

	directory, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	dirInfo, _ := directory.Stat()
	if err := checkSigningKeyHandle(directory, dirInfo); errorCode(err) != ErrInvalidInput {
		t.Fatalf("directory handle accepted: %v", err)
	}
}

func TestCheckSigningKeyHandleRejectsBroadPermissionsOnTheOpenFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not meaningful on Windows")
	}
	_, private, _ := ed25519.GenerateKey(cryptorand.Reader)
	path := writeKeyFile(t, []byte(hex.EncodeToString(private)), 0o600)
	// The path was inspected while it was still private ...
	inspected, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	// ... and became world-readable before the handle was examined.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	handle, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	if err := checkSigningKeyHandle(handle, inspected); errorCode(err) != ErrInvalidInput {
		t.Fatalf("broad permissions on the open file were not caught: %v", err)
	}
}

func TestWriteFileAtomicSyncsTheDirectoryAfterTheRename(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")
	var syncedDir string
	var contentWhenSynced []byte
	original := syncDirectoryAfterRename
	syncDirectoryAfterRename = func(directory string) {
		syncedDir = directory
		contentWhenSynced, _ = os.ReadFile(path)
	}
	defer func() { syncDirectoryAfterRename = original }()

	if err := WriteFileAtomic(path, []byte("renewed"), 0o644); err != nil {
		t.Fatal(err)
	}
	if syncedDir != dir || string(contentWhenSynced) != "renewed" {
		t.Fatalf("directory sync dir=%q content-at-sync=%q: want the parent directory after the rename", syncedDir, contentWhenSynced)
	}

	// A failed write must not claim durability it does not have.
	syncedDir = ""
	if err := WriteFileAtomic(filepath.Join(dir, "absent", "x"), []byte("x"), 0o644); err == nil {
		t.Fatal("write into a missing directory succeeded")
	}
	if syncedDir != "" {
		t.Fatalf("directory synced after a failed write: %q", syncedDir)
	}
}

func TestSyncDirectoryIsBestEffort(t *testing.T) {
	syncDirectory(t.TempDir())                        // existing directory: no panic
	syncDirectory(filepath.Join(t.TempDir(), "gone")) // missing directory: ignored
}
