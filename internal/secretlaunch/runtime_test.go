package secretlaunch

import (
	"context"
	"io"
	"strings"
	"testing"
)

type fakeCommandRunner struct {
	calls [][]string
	out   []byte
	err   error
}

func (r *fakeCommandRunner) Run(_ context.Context, name string, args ...string) ([]byte, []byte, error) {
	call := append([]string{name}, args...)
	r.calls = append(r.calls, call)
	return append([]byte(nil), r.out...), nil, r.err
}

type fakeAttachRunner struct{}

func (fakeAttachRunner) Attach(context.Context, string, ...string) (io.ReadWriteCloser, error) {
	return nil, errSynthetic
}

func TestValidateRenderedModelRejectsSecretEnvironmentAndAutonomousRestart(t *testing.T) {
	model := fixtureModel()
	model.Services[0].Environment = map[string]string{"DB_PASSWORD": "synthetic-sentinel"}
	if err := ValidateRenderedModel(model); errorCode(err) != ErrRuntime || strings.Contains(err.Error(), "synthetic-sentinel") {
		t.Fatalf("secret environment error = %v", err)
	}
	model = fixtureModel()
	model.Services[0].Restart = "unless-stopped"
	if err := ValidateRenderedModel(model); errorCode(err) != ErrRuntime {
		t.Fatalf("restart policy code = %v", errorCode(err))
	}
	model = fixtureModel()
	model.Services[0].OpenStdin = false
	if err := ValidateRenderedModel(model); errorCode(err) != ErrRuntime {
		t.Fatalf("stdin policy code = %v", errorCode(err))
	}
}

func TestDockerRuntimeRequiresExplicitInvocationAndUsesNoShellOrSecretEnv(t *testing.T) {
	runner := &fakeCommandRunner{out: []byte("container-id\n")}
	docker := NewDockerRuntime("docker", runner, fakeAttachRunner{}, false)
	if _, err := docker.Create(context.Background(), fixtureModel().Services[0], map[string]string{"com.skret.secret-launch": "v2"}); errorCode(err) != ErrNotInvoked {
		t.Fatalf("implicit Docker call code = %v", errorCode(err))
	}
	if len(runner.calls) != 0 {
		t.Fatal("implicit Docker call reached command runner")
	}
	docker.ExplicitInvoke = true
	service := fixtureModel().Services[0]
	container, err := docker.Create(context.Background(), service, map[string]string{"com.skret.secret-launch": "v2", "com.skret.role": "api"})
	if err != nil {
		t.Fatal(err)
	}
	if container.ID != "container-id" {
		t.Fatalf("container id = %q", container.ID)
	}
	call := strings.Join(runner.calls[0], " ")
	for _, forbidden := range []string{"synthetic-sentinel", "sh -c"} {
		if strings.Contains(call, forbidden) {
			t.Fatalf("Docker argv contains %q", forbidden)
		}
	}
	for _, required := range []string{"create", "--restart no", "--interactive", "--attach stdin", "--user 1000:1000", "--env LOG_LEVEL=info", "--label com.example.component=api"} {
		if !strings.Contains(call, required) {
			t.Fatalf("Docker argv missing %q: %s", required, call)
		}
	}
}

func TestExactLabelsAndDependencyOrdering(t *testing.T) {
	manifest := fixtureManifest()
	labels := OwnershipLabels(manifest)
	if !ExactLabels(labels, cloneLabels(labels)) {
		t.Fatal("identical labels not exact")
	}
	withExtra := cloneLabels(labels)
	withExtra["extra"] = "metadata"
	if ExactLabels(withExtra, labels) {
		t.Fatal("extra label was treated as exact ownership")
	}
	services := fixtureModel().Services
	db := fixtureModel().Services[0]
	db.Name = "db"
	db.Image = "registry.example/db@sha256:" + strings.Repeat("2", 64)
	db.Argv = []string{"/usr/local/bin/skret-secret-helper", "--runtime", "docker-prod", "--service", "db"}
	db.Labels = map[string]string{"com.example.component": "db"}
	db.Dependencies = []string{}
	db.WrapperDigest = digestFixture("g")
	db.Child = ChildSpec{Argv: []string{"/app/db"}, User: "current", Environment: map[string]string{"LOG_LEVEL": "info"}}
	services = append(services, db)
	services[0].Dependencies = []string{"db"}
	ordered, err := OrderServices(services)
	if err != nil {
		t.Fatal(err)
	}
	if ordered[0].Name != "db" || ordered[1].Name != "api" {
		t.Fatalf("dependency order = %v", ordered)
	}
	services[1].Dependencies = []string{"api"}
	if _, err := OrderServices(services); errorCode(err) != ErrRuntime {
		t.Fatal("dependency cycle was accepted")
	}
}

func TestModelDigestBindsEverySignedServiceField(t *testing.T) {
	model := fixtureModel()
	originalDigest := model.ComposeDigest
	model.Services[0].Labels["com.example.zone"] = "private"
	if err := ValidateRenderedModel(model); errorCode(err) != ErrBinding {
		t.Fatalf("stale model digest code = %v", errorCode(err))
	}
	model = fixtureModel()
	model.Services[0].Child.Environment = map[string]string{"LOG_LEVEL": "debug"}
	if err := ValidateRenderedModel(model); errorCode(err) != ErrRuntime {
		t.Fatalf("child environment mismatch code = %v", errorCode(err))
	}
	model = fixtureModel()
	model.Services[0].Environment["LOG_LEVEL"] = "debug"
	model.Services[0].Child.Environment["LOG_LEVEL"] = "debug"
	digest, err := ModelDigest(model)
	if err != nil {
		t.Fatal(err)
	}
	model.ComposeDigest = digest
	if err := ValidateManifestModel(fixtureManifest(), model); errorCode(err) != ErrBinding {
		t.Fatalf("manifest/model environment mismatch code = %v", errorCode(err))
	}
	if originalDigest == model.ComposeDigest {
		t.Fatal("model digest did not change after signed field mutation")
	}
}
