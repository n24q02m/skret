package statedir

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setFakeHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	return home
}

func TestValidateAndResolveProfile(t *testing.T) {
	t.Setenv(EnvProfile, "")
	p, err := ResolveProfile("")
	require.NoError(t, err)
	assert.Equal(t, "", p)

	t.Setenv(EnvProfile, "work-team.01")
	p, err = ResolveProfile("")
	require.NoError(t, err)
	assert.Equal(t, "work-team.01", p)

	p, err = ResolveProfile("explicit")
	require.NoError(t, err)
	assert.Equal(t, "explicit", p)

	for _, bad := range []string{".", "..", "a/b", `a\b`, "bad profile", "-leading", "toolong-" + string(make([]byte, 70))} {
		assert.Error(t, ValidateProfile(bad), "expected error for %q", bad)
		_, err := ResolveProfile(bad)
		assert.Error(t, err)
	}
}

func TestDirAndDirOrDot(t *testing.T) {
	home := setFakeHome(t)
	d, err := Dir("")
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(home, ".n24q02m", "skret"), d)

	pdir, err := Dir("staging")
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(home, ".n24q02m", "skret", "profiles", "staging"), pdir)

	_, err = Dir("../escape")
	assert.Error(t, err)

	assert.Equal(t, filepath.Join(home, ".n24q02m", "skret"), DirOrDot(""))
	assert.Equal(t, filepath.Join(home, ".n24q02m", "skret", "profiles", "staging"), DirOrDot("staging"))

	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	t.Setenv("HOMEDRIVE", "")
	t.Setenv("HOMEPATH", "")
	assert.Equal(t, filepath.Join(".", ".n24q02m", "skret"), DirOrDot("../invalid"))
	assert.Equal(t, filepath.Join(".", ".n24q02m", "skret", "profiles", "work"), DirOrDot("work"))
}

func TestMigrateLegacyFile_CopiesNonDestructively(t *testing.T) {
	home := setFakeHome(t)
	t.Setenv(EnvProfile, "")

	legacyPath := filepath.Join(home, ".skret", "credentials.yaml")
	require.NoError(t, os.MkdirAll(filepath.Dir(legacyPath), 0o700))
	require.NoError(t, os.WriteFile(legacyPath, []byte("version: \"1\"\n"), 0o600))

	dstPath := filepath.Join(home, ".n24q02m", "skret", "credentials.yaml")
	require.NoError(t, MigrateLegacyFile(dstPath, "credentials.yaml"))

	got, err := os.ReadFile(dstPath)
	require.NoError(t, err)
	assert.Equal(t, "version: \"1\"\n", string(got))

	// Source remains intact (non-destructive).
	legacyAfter, err := os.ReadFile(legacyPath)
	require.NoError(t, err)
	assert.Equal(t, "version: \"1\"\n", string(legacyAfter))

	// Existing destination is never overwritten.
	require.NoError(t, os.WriteFile(dstPath, []byte("updated\n"), 0o600))
	require.NoError(t, MigrateLegacyFile(dstPath, "credentials.yaml"))
	got2, err := os.ReadFile(dstPath)
	require.NoError(t, err)
	assert.Equal(t, "updated\n", string(got2))
}

func TestMigrateLegacyFile_SkippedWithProfileAndMissingAndSymlink(t *testing.T) {
	home := setFakeHome(t)
	dstPath := filepath.Join(home, ".n24q02m", "skret", "credentials.yaml")

	// Missing source is a no-op.
	t.Setenv(EnvProfile, "")
	require.NoError(t, MigrateLegacyFile(dstPath, "credentials.yaml"))
	assert.NoFileExists(t, dstPath)

	// Legacy exists, but SKRET_PROFILE set -> skipped.
	legacyPath := filepath.Join(home, ".skret", "credentials.yaml")
	require.NoError(t, os.MkdirAll(filepath.Dir(legacyPath), 0o700))
	require.NoError(t, os.WriteFile(legacyPath, []byte("v1"), 0o600))
	t.Setenv(EnvProfile, "work")
	require.NoError(t, MigrateLegacyFile(dstPath, "credentials.yaml"))
	assert.NoFileExists(t, dstPath)

	if runtime.GOOS != "windows" {
		t.Setenv(EnvProfile, "")
		sym := filepath.Join(home, ".skret", "sym.yaml")
		require.NoError(t, os.Symlink(legacyPath, sym))
		symDst := filepath.Join(home, ".n24q02m", "skret", "sym.yaml")
		require.NoError(t, MigrateLegacyFile(symDst, "sym.yaml"))
		assert.NoFileExists(t, symDst)
	}
}

func TestMigrateLegacyDir_CopiesFilesNonDestructively(t *testing.T) {
	home := setFakeHome(t)
	t.Setenv(EnvProfile, "")

	dstDir := filepath.Join(home, ".n24q02m", "skret", "sync-state")
	// Missing legacy dir -> no-op.
	require.NoError(t, MigrateLegacyDir(dstDir, "sync-state"))
	assert.NoDirExists(t, dstDir)

	legacyDir := filepath.Join(home, ".skret", "sync-state")
	require.NoError(t, os.MkdirAll(filepath.Join(legacyDir, "subdir"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(legacyDir, "v1-a.json"), []byte(`{"k":1}`), 0o600))

	require.NoError(t, MigrateLegacyDir(dstDir, "sync-state"))
	raw, err := os.ReadFile(filepath.Join(dstDir, "v1-a.json"))
	require.NoError(t, err)
	assert.Equal(t, `{"k":1}`, string(raw))
	assert.NoDirExists(t, filepath.Join(dstDir, "subdir"))
	// Legacy still exists.
	assert.FileExists(t, filepath.Join(legacyDir, "v1-a.json"))

	// Second call when dstDir exists is a no-op.
	require.NoError(t, MigrateLegacyDir(dstDir, "sync-state"))

	// Skipped when SKRET_PROFILE is set.
	t.Setenv(EnvProfile, "work")
	dstWork := filepath.Join(home, ".n24q02m", "skret", "profiles", "work", "sync-state")
	require.NoError(t, MigrateLegacyDir(dstWork, "sync-state"))
	assert.NoDirExists(t, dstWork)
}

func TestHomeErrorAndEdgeBranches(t *testing.T) {
	origHome := userHomeDir
	t.Cleanup(func() { userHomeDir = origHome })
	userHomeDir = func() (string, error) { return "", os.ErrNotExist }

	_, err := Dir("work")
	require.Error(t, err)
	assert.Equal(t, filepath.Join(".", ".n24q02m", "skret", "profiles", "work"), DirOrDot("work"))
	assert.Equal(t, filepath.Join(".", ".n24q02m", "skret"), DirOrDot("../bad"))

	_, err = LegacyFilePath("credentials.yaml")
	require.Error(t, err)

	t.Setenv(EnvProfile, "")
	dstFile := filepath.Join(t.TempDir(), "creds.yaml")
	require.NoError(t, MigrateLegacyFile(dstFile, "credentials.yaml"))
	dstDir := filepath.Join(t.TempDir(), "sync")
	require.NoError(t, MigrateLegacyDir(dstDir, "sync-state"))

	userHomeDir = origHome
	home := setFakeHome(t)

	// Legacy source is a directory for MigrateLegacyFile -> skipped cleanly.
	legacyAsDir := filepath.Join(home, ".skret", "isdir")
	require.NoError(t, os.MkdirAll(legacyAsDir, 0o700))
	require.NoError(t, MigrateLegacyFile(filepath.Join(home, ".n24q02m", "skret", "isdir"), "isdir"))
	assert.NoFileExists(t, filepath.Join(home, ".n24q02m", "skret", "isdir"))

	// Legacy source is a regular file for MigrateLegacyDir -> skipped cleanly.
	legacyAsFile := filepath.Join(home, ".skret", "isfile")
	require.NoError(t, os.WriteFile(legacyAsFile, []byte("x"), 0o600))
	require.NoError(t, MigrateLegacyDir(filepath.Join(home, ".n24q02m", "skret", "isfile"), "isfile"))
	assert.NoDirExists(t, filepath.Join(home, ".n24q02m", "skret", "isfile"))

	// Destination parent blocked by a regular file -> returns error from MigrateLegacyFile / MigrateLegacyDir.
	legacySrc := filepath.Join(home, ".skret", "ok.yaml")
	require.NoError(t, os.WriteFile(legacySrc, []byte("v1"), 0o600))
	blockingParent := filepath.Join(t.TempDir(), "file-blocker")
	require.NoError(t, os.WriteFile(blockingParent, []byte("blocker"), 0o600))
	require.Error(t, MigrateLegacyFile(filepath.Join(blockingParent, "ok.yaml"), "ok.yaml"))

	legacySubDir := filepath.Join(home, ".skret", "state")
	require.NoError(t, os.MkdirAll(legacySubDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(legacySubDir, "a.json"), []byte("1"), 0o600))
	require.Error(t, MigrateLegacyDir(filepath.Join(blockingParent, "state"), "state"))

	// copyRegularFile fails when destination is a non-empty directory, src path invalid, or MkdirAll blocked.
	badDst := filepath.Join(t.TempDir(), "target")
	require.NoError(t, os.MkdirAll(filepath.Join(badDst, "nested"), 0o700))
	require.Error(t, copyRegularFile(legacySrc, badDst))
	require.Error(t, copyRegularFile(legacySrc, filepath.Join(blockingParent, "sub", "ok.yaml")))
	require.Error(t, copyRegularFile(filepath.Join(home, ".skret", "bad\x00src"), filepath.Join(t.TempDir(), "x")))

	// Stat error on NUL path (non-ErrNotExist).
	require.Error(t, MigrateLegacyFile(filepath.Join(t.TempDir(), "bad\x00file"), "ok.yaml"))
	require.Error(t, MigrateLegacyDir(filepath.Join(t.TempDir(), "bad\x00dir"), "state"))

	// WriteFile failure via closed file in writeAndCloseTemp.
	f, err := os.CreateTemp(t.TempDir(), "closed-*")
	require.NoError(t, err)
	require.NoError(t, f.Close())
	require.Error(t, writeAndCloseTemp(f, []byte("abc")))

	if runtime.GOOS != "windows" {
		symDir := filepath.Join(home, ".skret", "symdir")
		require.NoError(t, os.Symlink(legacySubDir, symDir))
		require.NoError(t, MigrateLegacyDir(filepath.Join(home, ".n24q02m", "skret", "symdir"), "symdir"))
	}

	// Simulate readDir / readFile failures deterministically on all OSes.
	origReadDir := readDir
	readDir = func(string) ([]os.DirEntry, error) { return nil, os.ErrPermission }
	require.ErrorIs(t, MigrateLegacyDir(filepath.Join(t.TempDir(), "rd-err"), "state"), os.ErrPermission)
	readDir = origReadDir

	origReadFile := readFile
	readFile = func(string) ([]byte, error) { return nil, os.ErrPermission }
	require.ErrorIs(t, MigrateLegacyDir(filepath.Join(t.TempDir(), "rf-err"), "state"), os.ErrPermission)
	readFile = origReadFile

	origCreateTemp := createTemp
	createTemp = func(string, string) (*os.File, error) { return nil, os.ErrPermission }
	require.ErrorIs(t, copyRegularFile(legacySrc, filepath.Join(t.TempDir(), "ct-err")), os.ErrPermission)

	closedTmp, err := os.CreateTemp(t.TempDir(), "closed-migrate-*")
	require.NoError(t, err)
	require.NoError(t, closedTmp.Close())
	createTemp = func(string, string) (*os.File, error) { return closedTmp, nil }
	require.Error(t, copyRegularFile(legacySrc, filepath.Join(t.TempDir(), "wc-err")))
	createTemp = origCreateTemp
}
