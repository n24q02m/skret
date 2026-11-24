package statedir

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	// VendorDir is the root directory under $HOME for n24q02m tools.
	VendorDir = ".n24q02m"
	// ToolName is the subdirectory for skret under VendorDir.
	ToolName = "skret"
	// LegacyDirName is the pre-W10 home subdirectory for non-destructive migration.
	LegacyDirName = ".skret"
	// EnvProfile selects an isolated skret profile namespace under profiles/<name>.
	EnvProfile = "SKRET_PROFILE"
)

var (
	validProfilePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	userHomeDir         = os.UserHomeDir
	readDir             = os.ReadDir
	readFile            = os.ReadFile
)

// ValidateProfile validates a non-empty profile name. Empty string means default profile.
func ValidateProfile(profile string) error {
	if profile == "" {
		return nil
	}
	if profile == "." || profile == ".." || strings.ContainsAny(profile, `/\`) {
		return fmt.Errorf("statedir: invalid profile name %q", profile)
	}
	if !validProfilePattern.MatchString(profile) {
		return fmt.Errorf("statedir: invalid profile name %q", profile)
	}
	return nil
}

// ResolveProfile returns override when non-empty, else SKRET_PROFILE from env,
// validated for filesystem safety.
func ResolveProfile(override string) (string, error) {
	candidate := strings.TrimSpace(override)
	if candidate == "" {
		candidate = strings.TrimSpace(os.Getenv(EnvProfile))
	}
	if err := ValidateProfile(candidate); err != nil {
		return "", err
	}
	return candidate, nil
}

// Dir returns ~/.n24q02m/skret (or ~/.n24q02m/skret/profiles/<profile> when set).
func Dir(profile string) (string, error) {
	if err := ValidateProfile(profile); err != nil {
		return "", err
	}
	home, err := userHomeDir()
	if err != nil {
		return "", err
	}
	return dirFromHome(home, profile), nil
}

// DirOrDot resolves Dir(profile) falling back to "." when UserHomeDir fails.
func DirOrDot(profile string) string {
	dir, err := Dir(profile)
	if err == nil {
		return dir
	}
	if ValidateProfile(profile) != nil {
		profile = ""
	}
	return dirFromHome(".", profile)
}

func dirFromHome(home, profile string) string {
	base := filepath.Join(home, VendorDir, ToolName)
	if profile == "" {
		return base
	}
	return filepath.Join(base, "profiles", profile)
}

// LegacyFilePath returns ~/.skret/<rel> for the current home directory.
func LegacyFilePath(rel string) (string, error) {
	home, err := userHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, LegacyDirName, rel), nil
}

// MigrateLegacyFile performs a non-destructive one-time copy from
// ~/.skret/<rel> to dstPath when no profile override is active and dstPath does
// not exist yet. Symlinks in the legacy location are skipped.
func MigrateLegacyFile(dstPath, rel string) error {
	if strings.TrimSpace(os.Getenv(EnvProfile)) != "" {
		return nil
	}
	if _, err := os.Stat(dstPath); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	srcPath, err := LegacyFilePath(rel)
	if err != nil {
		return nil //nolint:nilerr // missing home directory skips best-effort legacy migration
	}
	return copyRegularFile(srcPath, dstPath)
}

// MigrateLegacyDir performs a non-destructive one-time copy of regular files
// from ~/.skret/<rel> to dstDir when no profile override is active and dstDir
// does not exist yet. Subdirectories and symlinks are skipped.
func MigrateLegacyDir(dstDir, rel string) error {
	if strings.TrimSpace(os.Getenv(EnvProfile)) != "" {
		return nil
	}
	if _, err := os.Stat(dstDir); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	srcDir, err := LegacyFilePath(rel)
	if err != nil {
		return nil //nolint:nilerr // missing home directory skips best-effort legacy migration
	}
	info, err := os.Lstat(srcDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil
	}
	entries, err := readDir(srcDir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dstDir, 0o700); err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 || entry.IsDir() {
			continue
		}
		if err := copyRegularFile(filepath.Join(srcDir, entry.Name()), filepath.Join(dstDir, entry.Name())); err != nil {
			return err
		}
	}
	return nil
}

func copyRegularFile(srcPath, dstPath string) error {
	info, err := os.Lstat(srcPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil
	}
	data, err := readFile(srcPath) //nolint:gosec // srcPath is validated legacy file under ~/.skret
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dstPath), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dstPath), ".migrate-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if err := writeAndCloseTemp(tmp, data); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, dstPath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

func writeAndCloseTemp(tmp *os.File, data []byte) error {
	err := tmp.Chmod(0o600)
	if err == nil {
		_, err = tmp.Write(data)
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	return err
}
