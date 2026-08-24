package secretlaunch

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestReadRegularFileRejectsOversizeAndSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("synthetic-sentinel"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRegularFile(target, 4); errorCode(err) != ErrInvalidInput {
		t.Fatalf("oversize file code = %v", errorCode(err))
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := ReadRegularFile(link, 64); errorCode(err) != ErrInvalidInput {
		t.Fatalf("symlink file code = %v", errorCode(err))
	}
}

func TestVerifyRegularFileDigestRequiresExactBytes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "artifact")
	contents := []byte("artifact-bytes")
	if err := os.WriteFile(path, contents, 0600); err != nil {
		t.Fatal(err)
	}
	manifest := fixtureManifest()
	canonical, err := manifest.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRegularFileDigest(path, digestForBytes(contents), int64(len(contents))); err != nil {
		t.Fatal(err)
	}
	if err := VerifyRegularFileDigest(path, digestForBytes(canonical), 1<<20); errorCode(err) != ErrBinding {
		t.Fatalf("wrong digest code = %v", errorCode(err))
	}
}

func digestForBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return fmt.Sprintf("sha256:%x", digest[:])
}
