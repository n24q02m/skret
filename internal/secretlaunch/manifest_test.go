package secretlaunch

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"
)

func TestParseManifestRejectsDuplicateUnknownAndNoncanonicalJSON(t *testing.T) {
	manifest := fixtureManifest()
	canonical, err := manifest.canonicalBytesUnchecked()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseManifest(canonical); err != nil {
		t.Fatalf("canonical manifest rejected: %v", err)
	}
	duplicate := bytes.Replace(canonical, []byte(`"version":"v2"`), []byte(`"version":"v2","version":"v2"`), 1)
	if _, err := ParseManifest(duplicate); errorCode(err) != ErrDuplicateField {
		t.Fatalf("duplicate field code = %v", errorCode(err))
	}
	unknown := append([]byte(nil), canonical[:len(canonical)-1]...)
	unknown = append(unknown, []byte(`,"unknown":1}`)...)
	if _, err := ParseManifest(unknown); errorCode(err) != ErrUnknownField {
		t.Fatalf("unknown field code = %v", errorCode(err))
	}
	spaced := []byte(" " + string(canonical))
	if _, err := ParseManifest(spaced); errorCode(err) != ErrCanonical {
		t.Fatalf("noncanonical code = %v", errorCode(err))
	}
}

func TestVerifySignedManifestRejectsTamperExpiryRoleAndKeyVersion(t *testing.T) {
	manifest, signed, policy, private := signedFixture(t)
	if _, err := VerifySignedManifest(signed, policy, time.Now()); err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), signed...)
	tampered[len(tampered)-3] ^= 1
	if _, err := VerifySignedManifest(tampered, policy, time.Now()); errorCode(err) != ErrSignature && errorCode(err) != ErrCanonical {
		t.Fatalf("tampered signature code = %v", errorCode(err))
	}
	if err := VerifyManifest(manifest, []byte("bad"), "fixture-key", policy, time.Now()); errorCode(err) != ErrSignature {
		t.Fatalf("bad signature code = %v", errorCode(err))
	}
	if err := manifest.MatchBinding(LaunchBinding{RuntimeID: manifest.RuntimeID, Service: "missing", Role: manifest.Role}); errorCode(err) != ErrBinding {
		t.Fatalf("role binding code = %v", errorCode(err))
	}
	manifest.IssuedAt = time.Now().Add(-2 * time.Minute).Unix()
	manifest.ExpiresAt = time.Now().Add(-time.Minute).Unix()
	if err := VerifyManifest(manifest, ed25519.Sign(private, mustMarshal(manifest)), "fixture-key", policy, time.Now()); errorCode(err) != ErrExpired {
		t.Fatalf("expired manifest code = %v", errorCode(err))
	}
	manifest = fixtureManifest()
	manifest.Services[0].Keys[0].Version = "2"
	if err := VerifyManifest(manifest, ed25519.Sign(private, mustMarshal(manifest)), "fixture-key", policy, time.Now()); errorCode(err) != ErrKey {
		t.Fatalf("key allowlist code = %v", errorCode(err))
	}
	if err := manifest.MatchBinding(LaunchBinding{RuntimeID: manifest.RuntimeID, Service: "api", Role: manifest.Role, Generation: manifest.Generation, ExpiresAt: manifest.ExpiresAt, Nonce: manifest.Nonce}); err != nil {
		t.Fatal(err)
	}
}

func TestVerifySignedManifestRejectsUnknownSigningKeyAndVersion(t *testing.T) {
	manifest, signed, policy, _ := signedFixture(t)
	public := policy.AllowedSigningKeys["fixture-key"]
	policy.AllowedSigningKeys = map[string]ed25519.PublicKey{"other-key": public}
	if _, err := VerifySignedManifest(signed, policy, time.Now()); errorCode(err) != ErrSignature {
		t.Fatalf("unknown key code = %v", errorCode(err))
	}
	_, signed, policy, _ = signedFixture(t)
	policy.AllowedVersions = map[string]bool{"v3": true}
	if _, err := VerifySignedManifest(signed, policy, time.Now()); errorCode(err) != ErrTrust {
		t.Fatalf("version code = %v", errorCode(err))
	}
	if !strings.Contains(manifest.Role, "prod") {
		t.Fatal("fixture role unexpectedly changed")
	}
}

func TestTrustDocumentCanonicalAndAllowlist(t *testing.T) {
	manifest, signed, policy, _ := signedFixture(t)
	_ = signed
	public := policy.AllowedSigningKeys["fixture-key"]
	encoded := encodePublicKey(public)
	data := []byte(`{"keys":{"fixture-key":"` + encoded + `"},"versions":["v2"],"runtime_ids":["docker-prod"],"roles":["prod-api"],"key_versions":{"APP_TOKEN":{"1":true}}}`)
	loaded, err := LoadTrustDocument(data)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySignedManifest(signed, loaded, time.Now()); err != nil {
		t.Fatal(err)
	}
	bad := bytes.Replace(data, []byte(`"roles":["prod-api"]`), []byte(`"roles":["prod-api"],"roles":["prod-api"]`), 1)
	if _, err := LoadTrustDocument(bad); err == nil {
		t.Fatal("expected malformed trust document rejection")
	}
	if manifest.Version != ManifestVersion {
		t.Fatal("fixture version changed")
	}
}

func TestManifestTimeWindowAndCanonicalDigestAreDeterministic(t *testing.T) {
	manifest := fixtureManifest()
	now := time.Unix(1_800_000_000, 0)
	manifest.IssuedAt = now.Add(-time.Minute).Unix()
	manifest.ExpiresAt = now.Add(10 * time.Minute).Unix()
	first, err := manifest.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	second, err := manifest.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("canonical bytes changed without a manifest mutation")
	}
	firstDigest, err := manifest.Digest()
	if err != nil {
		t.Fatal(err)
	}
	secondDigest, err := manifest.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if firstDigest != secondDigest {
		t.Fatal("manifest digest changed without a manifest mutation")
	}
	if err := manifest.ValidateAt(now); err != nil {
		t.Fatal(err)
	}
	tooLong := manifest
	tooLong.ExpiresAt = tooLong.IssuedAt + int64(MaxManifestTTL/time.Second) + 1
	if errorCode(tooLong.Validate()) != ErrTTL {
		t.Fatalf("too-long manifest code = %v", errorCode(tooLong.Validate()))
	}
	notYet := manifest
	if errorCode(notYet.ValidateAt(time.Unix(notYet.IssuedAt-1, 0))) != ErrNotYetValid {
		t.Fatalf("not-yet-valid code = %v", errorCode(notYet.ValidateAt(time.Unix(notYet.IssuedAt-1, 0))))
	}
	expired := manifest
	if errorCode(expired.ValidateAt(time.Unix(expired.ExpiresAt, 0))) != ErrExpired {
		t.Fatalf("expired code = %v", errorCode(expired.ValidateAt(time.Unix(expired.ExpiresAt, 0))))
	}
}
