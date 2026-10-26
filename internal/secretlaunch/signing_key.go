package secretlaunch

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const maxSigningKeyFileBytes = 4096

// ReadSigningKeyFile loads an Ed25519 private key (64-byte key or 32-byte
// seed; hex, base64, or raw) from a regular file that is not a symlink. On
// POSIX systems the file must not be accessible to group or others. The checks
// run on the open file, which is also the one that is read, so the path cannot
// be swapped in between. Errors never include file contents.
func ReadSigningKeyFile(path string) (ed25519.PrivateKey, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() > maxSigningKeyFileBytes {
		return nil, fail(ErrInvalidInput)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fail(ErrInvalidInput)
	}
	defer file.Close()
	if err := checkSigningKeyHandle(file, before); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(file, maxSigningKeyFileBytes+1))
	defer Zeroize(data)
	if err != nil || len(data) > maxSigningKeyFileBytes {
		return nil, fail(ErrInvalidInput)
	}
	return parseSigningKey(data)
}

// checkSigningKeyHandle accepts an open key file only if it is the regular file
// the path resolved to (before) and, on POSIX systems, is private to its owner.
// Permissions are read from the handle itself, never from an earlier lookup.
func checkSigningKeyHandle(file *os.File, before os.FileInfo) error {
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return fail(ErrInvalidInput)
	}
	if runtime.GOOS != "windows" && opened.Mode().Perm()&0o077 != 0 {
		return fail(ErrInvalidInput)
	}
	return nil
}

func parseSigningKey(data []byte) (ed25519.PrivateKey, error) {
	raw := data
	var decoded []byte
	defer func() { Zeroize(decoded) }()
	text := strings.TrimSpace(string(data))
	for _, decode := range []func(string) ([]byte, error){hex.DecodeString, base64.StdEncoding.DecodeString} {
		if out, err := decode(text); err == nil {
			decoded, raw = out, out
			break
		}
	}
	switch len(raw) {
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(append([]byte(nil), raw...)), nil
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	}
	return nil, fail(ErrInvalidInput)
}

// WriteFileAtomic replaces path with data: the content is written and synced
// to a temporary file in the same directory and then renamed over the target,
// so a reader sees either the complete old file or the complete new one.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) (err error) {
	if path == "" {
		return fail(ErrInvalidInput)
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".skret-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary file for %q: %w", path, err)
	}
	name := temporary.Name()
	defer func() {
		if err != nil {
			_ = temporary.Close()
			_ = os.Remove(name)
		}
	}()
	if _, err = temporary.Write(data); err != nil {
		return fmt.Errorf("write %q: %w", name, err)
	}
	if err = temporary.Sync(); err != nil {
		return fmt.Errorf("sync %q: %w", name, err)
	}
	if err = temporary.Chmod(perm); err != nil {
		return fmt.Errorf("chmod %q: %w", name, err)
	}
	if err = temporary.Close(); err != nil {
		return fmt.Errorf("close %q: %w", name, err)
	}
	if err = os.Rename(name, path); err != nil {
		return fmt.Errorf("replace %q: %w", path, err)
	}
	syncDirectoryAfterRename(filepath.Dir(path))
	return nil
}

// syncDirectoryAfterRename is a variable only so tests can observe the call.
var syncDirectoryAfterRename = syncDirectory

// syncDirectory flushes a directory entry so a completed rename survives power
// loss. It is best effort: not every platform or filesystem supports fsync on
// a directory (Windows does not), and the rename has already succeeded.
func syncDirectory(dir string) {
	if runtime.GOOS == "windows" {
		return
	}
	directory, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = directory.Sync()
	_ = directory.Close()
}
