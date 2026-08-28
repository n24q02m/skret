package secretlaunch

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
)

const (
	MaxSignedManifestBytes = 4 << 20
	MaxTrustDocumentBytes  = 1 << 20
	MaxRenderedModelBytes  = 8 << 20
)

// ReadRegularFile reads one bounded regular file without accepting symlinks or
// a path that changes identity while it is open.
func ReadRegularFile(path string, maximum int64) ([]byte, error) {
	if path == "" || maximum <= 0 {
		return nil, fail(ErrInvalidInput)
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() < 0 || before.Size() > maximum {
		return nil, fail(ErrInvalidInput)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fail(ErrInvalidInput)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return nil, fail(ErrInvalidInput)
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) > maximum {
		Zeroize(data)
		return nil, fail(ErrInvalidInput)
	}
	after, err := file.Stat()
	pathAfter, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || !os.SameFile(opened, after) || !os.SameFile(opened, pathAfter) ||
		after.Size() != opened.Size() || !after.ModTime().Equal(opened.ModTime()) || int64(len(data)) != opened.Size() {
		Zeroize(data)
		return nil, fail(ErrInvalidInput)
	}
	return data, nil
}

func VerifyRegularFileDigest(path, expected string, maximum int64) error {
	if !validDigest(expected) || path == "" || maximum <= 0 {
		return fail(ErrInvalidInput)
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() < 0 || before.Size() > maximum {
		return fail(ErrInvalidInput)
	}
	file, err := os.Open(path)
	if err != nil {
		return fail(ErrInvalidInput)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return fail(ErrInvalidInput)
	}
	digest := sha256.New()
	written, err := io.Copy(digest, io.LimitReader(file, maximum+1))
	after, statErr := file.Stat()
	pathAfter, pathErr := os.Lstat(path)
	if err != nil || statErr != nil || pathErr != nil || written > maximum || written != opened.Size() ||
		!os.SameFile(opened, after) || !os.SameFile(opened, pathAfter) ||
		after.Size() != opened.Size() || !after.ModTime().Equal(opened.ModTime()) {
		return fail(ErrInvalidInput)
	}
	actual := fmt.Sprintf("sha256:%x", digest.Sum(nil))
	if actual != expected {
		return fail(ErrBinding)
	}
	return nil
}
