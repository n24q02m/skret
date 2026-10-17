package secretlaunch

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const maxSigningKeyFileBytes = 4096

// ReadSigningKeyFile loads an Ed25519 private key (64-byte key or 32-byte
// seed; hex, base64, or raw) from a regular file that is not a symlink. On
// POSIX systems the file must not be accessible to group or others. Errors
// never include file contents.
func ReadSigningKeyFile(path string) (ed25519.PrivateKey, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, fail(ErrInvalidInput)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, fail(ErrInvalidInput)
	}
	data, err := ReadRegularFile(path, maxSigningKeyFileBytes)
	if err != nil {
		return nil, err
	}
	defer Zeroize(data)
	return parseSigningKey(data)
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
	return nil
}
