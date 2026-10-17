package secretlaunch

import (
	"os"
	"path"
	"path/filepath"
	"strings"
)

// ManifestMount delivers the renewed signed manifest to the helper inside each
// container. It bind-mounts one host directory read-only. A directory (not a
// single file) is mounted because the signer replaces the manifest by rename,
// and a file bind mount would keep pointing at the old inode.
//
// The directory may hold nothing but the manifest file (plus the signer's
// transient temporary file), so the signing key, trust document and rendered
// model can never be exposed to a container by a wrong path.
type ManifestMount struct {
	// HostDir is the absolute host directory that contains the manifest.
	HostDir string
	// ContainerDir is the absolute, clean mount point inside the container.
	ContainerDir string
	// FileName is the manifest file name inside HostDir.
	FileName string
}

const (
	signerTemporaryPrefix = ".skret-"
	signerTemporarySuffix = ".tmp"
)

// ContainerPath is where the helper must find the manifest.
func (m ManifestMount) ContainerPath() string {
	return path.Join(m.ContainerDir, m.FileName)
}

// Validate checks the mount definition and the current content of HostDir.
// It never reads file contents.
func (m ManifestMount) Validate() error {
	if !filepath.IsAbs(m.HostDir) || !mountSafe(m.HostDir) ||
		!path.IsAbs(m.ContainerDir) || m.ContainerDir == "/" || path.Clean(m.ContainerDir) != m.ContainerDir || !mountSafe(m.ContainerDir) ||
		m.FileName == "" || m.FileName == "." || m.FileName == ".." || strings.ContainsAny(m.FileName, `/\`) || !mountSafe(m.FileName) {
		return fail(ErrRuntime)
	}
	info, err := os.Lstat(m.HostDir)
	if err != nil || !info.IsDir() {
		return fail(ErrRuntime)
	}
	entries, err := os.ReadDir(m.HostDir)
	if err != nil {
		return fail(ErrRuntime)
	}
	for _, entry := range entries {
		name := entry.Name()
		temporary := strings.HasPrefix(name, signerTemporaryPrefix) && strings.HasSuffix(name, signerTemporarySuffix)
		if (name != m.FileName && !temporary) || !entry.Type().IsRegular() {
			return fail(ErrRuntime)
		}
	}
	return nil
}

// dockerArgs returns the single read-only bind mount for docker create.
func (m ManifestMount) dockerArgs() []string {
	return []string{"--mount", "type=bind,source=" + m.HostDir + ",target=" + m.ContainerDir + ",readonly"}
}

// checkArgv requires that the helper is told to read exactly the mounted file,
// so a wiring mistake fails before the container exists instead of leaving it
// without a manifest.
func (m ManifestMount) checkArgv(argv []string) error {
	found := 0
	for i, arg := range argv {
		if arg != "--manifest" {
			continue
		}
		found++
		if i+1 >= len(argv) || argv[i+1] != m.ContainerPath() {
			return fail(ErrRuntime)
		}
	}
	if found != 1 {
		return fail(ErrRuntime)
	}
	return nil
}

// mountSafe rejects characters that would let a path add or alter options in
// the comma-separated --mount value.
func mountSafe(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f || r == ',' || r == '"' {
			return false
		}
	}
	return value != ""
}
