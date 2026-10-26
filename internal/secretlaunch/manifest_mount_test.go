package secretlaunch

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testMountContainerDir = "/run/skret/manifest"

// mountFixture returns a delivery directory holding only manifest.json and a
// service whose helper argv points at the mounted file.
func mountFixture(t *testing.T) (ManifestMount, ServiceSpec) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	mount := ManifestMount{HostDir: dir, ContainerDir: testMountContainerDir, FileName: "manifest.json"}
	service := fixtureModel().Services[0]
	service.Argv = []string{
		"/usr/local/bin/skret-secret-helper",
		"--manifest", testMountContainerDir + "/manifest.json",
		"--runtime", "docker-prod", "--service", service.Name,
	}
	return mount, service
}

func createWithMount(t *testing.T, mount *ManifestMount, service ServiceSpec) (*fakeCommandRunner, error) {
	t.Helper()
	runner := &fakeCommandRunner{out: []byte("container-id\n")}
	docker := NewDockerRuntime("docker", runner, fakeAttachRunner{}, true)
	docker.ManifestMount = mount
	_, err := docker.Create(context.Background(), service, map[string]string{"com.skret.secret-launch": "v2"})
	return runner, err
}

func TestDockerRuntimeMountsOnlyTheManifestDirectoryReadOnly(t *testing.T) {
	mount, service := mountFixture(t)
	runner, err := createWithMount(t, &mount, service)
	if err != nil {
		t.Fatal(err)
	}
	call := runner.calls[0]
	var mounts []string
	for i, arg := range call {
		if arg == "--mount" || arg == "--volume" || arg == "-v" {
			mounts = append(mounts, arg+" "+call[i+1])
		}
	}
	want := "--mount type=bind,source=" + mount.HostDir + ",target=" + testMountContainerDir + ",readonly"
	if len(mounts) != 1 || mounts[0] != want {
		t.Fatalf("mounts = %q, want [%q]", mounts, want)
	}
	if strings.Index(strings.Join(call, " "), "--mount") > strings.Index(strings.Join(call, " "), "-- "+service.Image) {
		t.Fatal("mount flag must precede the image reference")
	}
}

func TestDockerRuntimeWithoutManifestMountAddsNoMount(t *testing.T) {
	_, service := mountFixture(t)
	runner, err := createWithMount(t, nil, service)
	if err != nil {
		t.Fatal(err)
	}
	if call := strings.Join(runner.calls[0], " "); strings.Contains(call, "--mount") || strings.Contains(call, "--volume") {
		t.Fatalf("unexpected mount: %s", call)
	}
}

func TestManifestMountToleratesSignerTemporaryFile(t *testing.T) {
	mount, service := mountFixture(t)
	if err := os.WriteFile(filepath.Join(mount.HostDir, ".skret-123456.tmp"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := createWithMount(t, &mount, service); err != nil {
		t.Fatalf("signer temporary file rejected: %v", err)
	}
}

func TestManifestMountRejectsDirectoryHoldingAnythingElse(t *testing.T) {
	for name, populate := range map[string]func(dir string) error{
		"signing key":    func(dir string) error { return os.WriteFile(filepath.Join(dir, "signing.key"), []byte("x"), 0o600) },
		"trust document": func(dir string) error { return os.WriteFile(filepath.Join(dir, "trust.json"), []byte("{}"), 0o644) },
		"rendered model": func(dir string) error { return os.WriteFile(filepath.Join(dir, "model.json"), []byte("{}"), 0o644) },
		"subdirectory":   func(dir string) error { return os.Mkdir(filepath.Join(dir, "nested"), 0o755) },
		"lookalike temp": func(dir string) error { return os.WriteFile(filepath.Join(dir, "skret-1.tmp"), []byte("x"), 0o600) },
		"temp subfolder": func(dir string) error { return os.Mkdir(filepath.Join(dir, ".skret-1.tmp"), 0o755) },
		"unrelated dot":  func(dir string) error { return os.WriteFile(filepath.Join(dir, ".env"), []byte("x"), 0o600) },
		"manifest backup": func(dir string) error {
			return os.WriteFile(filepath.Join(dir, "manifest.json.bak"), []byte("x"), 0o600)
		},
	} {
		t.Run(name, func(t *testing.T) {
			mount, service := mountFixture(t)
			if err := populate(mount.HostDir); err != nil {
				t.Fatal(err)
			}
			runner, err := createWithMount(t, &mount, service)
			if errorCode(err) != ErrRuntime {
				t.Fatalf("err = %v", err)
			}
			if len(runner.calls) != 0 {
				t.Fatal("docker was called with an unsafe mount")
			}
		})
	}
}

func TestManifestMountRejectsSymlinkedManifestEntry(t *testing.T) {
	mount, service := mountFixture(t)
	outside := filepath.Join(t.TempDir(), "signing.key")
	if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(mount.HostDir, "manifest.json")
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := createWithMount(t, &mount, service); errorCode(err) != ErrRuntime {
		t.Fatalf("symlinked manifest accepted: %v", err)
	}
}

func TestManifestMountRejectsUnusableHostDirectory(t *testing.T) {
	mount, service := mountFixture(t)
	file := filepath.Join(t.TempDir(), "plain-file")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, dir := range map[string]string{
		"missing":  filepath.Join(t.TempDir(), "absent"),
		"file":     file,
		"relative": "relative/dir",
		"empty":    "",
		"comma":    mount.HostDir + ",readonly=false",
		"quote":    mount.HostDir + `"`,
		"newline":  mount.HostDir + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			bad := mount
			bad.HostDir = dir
			runner, err := createWithMount(t, &bad, service)
			if errorCode(err) != ErrRuntime || len(runner.calls) != 0 {
				t.Fatalf("err = %v, calls = %d", err, len(runner.calls))
			}
		})
	}
}

func TestManifestMountRejectsUnsafeContainerSide(t *testing.T) {
	mount, service := mountFixture(t)
	cases := map[string]func(m *ManifestMount){
		"relative dir":      func(m *ManifestMount) { m.ContainerDir = "run/skret" },
		"root dir":          func(m *ManifestMount) { m.ContainerDir = "/" },
		"unclean dir":       func(m *ManifestMount) { m.ContainerDir = "/run/../etc" },
		"trailing slash":    func(m *ManifestMount) { m.ContainerDir = "/run/skret/" },
		"comma in dir":      func(m *ManifestMount) { m.ContainerDir = "/run,target=/etc" },
		"empty file name":   func(m *ManifestMount) { m.FileName = "" },
		"dot file name":     func(m *ManifestMount) { m.FileName = ".." },
		"separator in name": func(m *ManifestMount) { m.FileName = "sub/manifest.json" },
		"backslash name":    func(m *ManifestMount) { m.FileName = `sub\manifest.json` },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			bad := mount
			mutate(&bad)
			runner, err := createWithMount(t, &bad, service)
			if errorCode(err) != ErrRuntime || len(runner.calls) != 0 {
				t.Fatalf("err = %v, calls = %d", err, len(runner.calls))
			}
		})
	}
}

func TestManifestMountRequiresHelperToReadTheMountedFile(t *testing.T) {
	mount, service := mountFixture(t)
	withArgv := func(argv ...string) ServiceSpec {
		s := service
		s.Argv = argv
		return s
	}
	helper := "/usr/local/bin/skret-secret-helper"
	for name, spec := range map[string]ServiceSpec{
		"no manifest flag":     withArgv(helper, "--runtime", "docker-prod"),
		"other path":           withArgv(helper, "--manifest", "/etc/skret/secret-launch/docker-prod.manifest.json"),
		"other file in dir":    withArgv(helper, "--manifest", testMountContainerDir+"/trust.json"),
		"dangling flag":        withArgv(helper, "--manifest"),
		"duplicate flag":       withArgv(helper, "--manifest", testMountContainerDir+"/manifest.json", "--manifest", testMountContainerDir+"/manifest.json"),
		"equals form":          withArgv(helper, "--manifest="+testMountContainerDir+"/manifest.json"),
		"flag value is a flag": withArgv(helper, "--manifest", "--trust"),
	} {
		t.Run(name, func(t *testing.T) {
			runner, err := createWithMount(t, &mount, spec)
			if errorCode(err) != ErrRuntime || len(runner.calls) != 0 {
				t.Fatalf("err = %v, calls = %d", err, len(runner.calls))
			}
		})
	}
}
