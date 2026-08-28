package secretlaunch

import (
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func fixtureAuthority() ServiceAuthority {
	return ServiceAuthority{
		Name:          "api",
		Image:         "registry.example/api@sha256:" + strings.Repeat("1", 64),
		User:          "1000:1000",
		Argv:          []string{"/usr/local/bin/skret-secret-helper", "--runtime", "docker-prod", "--service", "api"},
		Environment:   map[string]string{"LOG_LEVEL": "info"},
		Labels:        map[string]string{"com.example.component": "api"},
		Networks:      []string{"backend"},
		Restart:       "no",
		OpenStdin:     true,
		Health:        HealthSpec{Command: []string{"/bin/true"}, IntervalMS: 10, TimeoutMS: 10, Retries: 1},
		Dependencies:  []string{},
		Keys:          []ManifestKey{{Name: "APP_TOKEN", Version: "1", Env: "APP_TOKEN"}},
		WrapperDigest: digestFixture("c"),
		Child: ChildSpec{
			Argv: []string{"/bin/echo", "ready"}, User: "current",
			Environment: map[string]string{"LOG_LEVEL": "info"},
		},
	}
}

func fixtureModel() RenderedModel {
	authority := fixtureAuthority()
	model := RenderedModel{
		RuntimeID: "docker-prod",
		Services:  []ServiceSpec{serviceSpecFromAuthority(&authority)},
	}
	digest, err := ModelDigest(model)
	if err != nil {
		panic(err)
	}
	model.ComposeDigest = digest
	return model
}

func fixtureManifest() Manifest {
	now := time.Now()
	return Manifest{
		Version:    ManifestVersion,
		RuntimeID:  "docker-prod",
		Role:       "prod-api",
		Generation: 7,
		IssuedAt:   now.Add(-time.Minute).Unix(),
		ExpiresAt:  now.Add(10 * time.Minute).Unix(),
		Nonce:      "nonce-1234567890",
		Services:   []ServiceAuthority{fixtureAuthority()},
		Digests: ArtifactDigests{
			Helper:     digestFixture("a"),
			Supervisor: digestFixture("b"),
			Compose:    fixtureModel().ComposeDigest,
		},
	}
}

func digestFixture(char string) string { return "sha256:" + strings.Repeat(char, 64) }

func signedFixture(t *testing.T) (Manifest, []byte, TrustPolicy, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest := fixtureManifest()
	signed, err := SignManifest(manifest, "fixture-key", private, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	policy := TrustPolicy{
		AllowedSigningKeys: map[string]ed25519.PublicKey{"fixture-key": public},
		AllowedVersions:    map[string]bool{ManifestVersion: true},
		AllowedRuntimeIDs:  map[string]bool{manifest.RuntimeID: true},
		AllowedRoles:       map[string]bool{manifest.Role: true},
		KeyVersions: map[string]map[string]bool{
			manifest.Services[0].Keys[0].Name: {manifest.Services[0].Keys[0].Version: true},
		},
	}
	return manifest, signed, policy, private
}

func encodePublicKey(key ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(key)
}
