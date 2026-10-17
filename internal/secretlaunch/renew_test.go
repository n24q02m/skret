package secretlaunch

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"
)

// renewedWindow returns a copy of m with a later validity window and an
// otherwise identical launch authority.
func renewedWindow(m Manifest) Manifest {
	m.IssuedAt += 30
	m.ExpiresAt += 30
	return m
}

func noopSend(context.Context, io.ReadWriteCloser, Manifest, ServiceAuthority, SecretSet) error {
	return nil
}

func TestSupervisorKeepsContainersWhenManifestWindowIsRenewed(t *testing.T) {
	runtime := newFakeRuntime()
	provider := FetchFunc(func(context.Context, string, string) ([]byte, error) {
		return []byte("synthetic-sentinel"), nil
	})
	supervisor := NewSupervisor(runtime, provider)
	supervisor.Send = noopSend
	manifest := fixtureManifest()
	model := fixtureModel()
	first, err := supervisor.Reconcile(context.Background(), model, manifest)
	if err != nil || len(first.Created) != 1 {
		t.Fatalf("initial reconcile = %+v, %v", first, err)
	}
	runtime.mu.Lock()
	runtime.calls = nil
	runtime.mu.Unlock()

	result, err := supervisor.Reconcile(context.Background(), model, renewedWindow(manifest))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Reused) != 1 || result.Reused[0] != "api" || len(result.Created) != 0 || result.Removed != 0 {
		t.Fatalf("renewal must reuse every container, got %+v", result)
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	for _, call := range runtime.calls {
		if strings.HasPrefix(call, "create:") || strings.HasPrefix(call, "remove:") {
			t.Fatalf("renewal must not create or remove containers; calls = %v", runtime.calls)
		}
	}
}

func TestAuthorityDigestIgnoresWindowButTracksAuthority(t *testing.T) {
	base := fixtureManifest()
	baseDigest, err := base.AuthorityDigest()
	if err != nil {
		t.Fatal(err)
	}
	renewedDigest, err := renewedWindow(base).AuthorityDigest()
	if err != nil || renewedDigest != baseDigest {
		t.Fatalf("window change altered authority digest: %v", err)
	}
	fullBase, _ := base.Digest()
	fullRenewed, _ := renewedWindow(base).Digest()
	if fullBase == fullRenewed {
		t.Fatal("full digest must still cover the window")
	}
	for name, mutate := range map[string]func(*Manifest){
		"generation": func(m *Manifest) { m.Generation++ },
		"nonce":      func(m *Manifest) { m.Nonce = "another-nonce-1234567890" },
		"role":       func(m *Manifest) { m.Role = "other-role" },
		"image": func(m *Manifest) {
			m.Services = []ServiceAuthority{fixtureAuthority()}
			m.Services[0].Image = "registry.example/api@sha256:" + strings.Repeat("2", 64)
		},
	} {
		changed := base
		mutate(&changed)
		digest, err := changed.AuthorityDigest()
		if err != nil || digest == baseDigest {
			t.Fatalf("%s change must alter authority digest (err=%v)", name, err)
		}
	}
	invalid := base
	invalid.Version = "v0"
	if _, err := invalid.AuthorityDigest(); err == nil {
		t.Fatal("invalid manifest must not yield an authority digest")
	}
}

func TestAuthorityBytesAreWindowIndependent(t *testing.T) {
	base := fixtureManifest()
	first, err := base.AuthorityBytes()
	if err != nil {
		t.Fatal(err)
	}
	second, err := renewedWindow(base).AuthorityBytes()
	if err != nil || string(first) != string(second) {
		t.Fatalf("authority bytes depend on window: %v", err)
	}
	full, _ := base.CanonicalBytes()
	if string(full) == string(first) {
		t.Fatal("authority bytes must differ from the full canonical bytes")
	}
}

func TestRenewManifestChangesOnlyTheWindow(t *testing.T) {
	base := fixtureManifest()
	now := time.Unix(base.IssuedAt+120, 0)
	renewed, err := RenewManifest(base, now, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if renewed.IssuedAt != now.Unix() || renewed.ExpiresAt != now.Add(10*time.Minute).Unix() {
		t.Fatalf("window = [%d,%d]", renewed.IssuedAt, renewed.ExpiresAt)
	}
	want, _ := base.AuthorityDigest()
	got, err := renewed.AuthorityDigest()
	if err != nil || got != want {
		t.Fatalf("authority changed on renewal: %v", err)
	}
	for _, ttl := range []time.Duration{0, -time.Minute, time.Millisecond, MaxManifestTTL + time.Second} {
		if _, err := RenewManifest(base, now, ttl); errorCode(err) != ErrTTL {
			t.Fatalf("ttl %v: err = %v", ttl, err)
		}
	}
	broken := base
	broken.Version = "v0"
	if _, err := RenewManifest(broken, now, time.Minute); errorCode(err) != ErrInvalidInput {
		t.Fatalf("invalid base: err = %v", err)
	}
}

func TestAcceptRenewal(t *testing.T) {
	current := fixtureManifest()
	now := time.Unix(current.IssuedAt+60, 0)
	renewed := renewedWindow(current)

	if err := AcceptRenewal(current, renewed, now); err != nil {
		t.Fatalf("valid renewal rejected: %v", err)
	}
	if err := AcceptRenewal(current, current, now); err != nil {
		t.Fatalf("identical manifest must be accepted idempotently: %v", err)
	}
	rollback := current
	rollback.ExpiresAt--
	if err := AcceptRenewal(current, rollback, now); errorCode(err) != ErrReplay {
		t.Fatalf("rollback err = %v", err)
	}
	generation := renewed
	generation.Generation++
	if err := AcceptRenewal(current, generation, now); errorCode(err) != ErrBinding {
		t.Fatalf("generation change err = %v", err)
	}
	other := renewed
	other.Services = []ServiceAuthority{fixtureAuthority()}
	other.Services[0].Argv = []string{"/usr/local/bin/skret-secret-helper", "--runtime", "docker-prod", "--service", "evil"}
	if err := AcceptRenewal(current, other, now); errorCode(err) != ErrBinding {
		t.Fatalf("service change err = %v", err)
	}
	expired := renewed
	if err := AcceptRenewal(current, expired, time.Unix(renewed.ExpiresAt, 0)); errorCode(err) != ErrExpired {
		t.Fatalf("expired candidate err = %v", err)
	}
	future := renewed
	if err := AcceptRenewal(current, future, time.Unix(renewed.IssuedAt-10, 0)); errorCode(err) != ErrNotYetValid {
		t.Fatalf("future candidate err = %v", err)
	}
	invalid := renewed
	invalid.Version = "v0"
	if err := AcceptRenewal(current, invalid, now); err == nil {
		t.Fatal("invalid candidate accepted")
	}
}
