package secretlaunch

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"time"
)

// MaxRenewalAge caps how old a signing template may be when it is renewed
// (one week). It bounds how long a stolen or forgotten signing key stays able
// to extend one launch, whatever --max-age an operator configures.
const MaxRenewalAge = 168 * time.Hour

// AuthorityBytes returns the canonical manifest bytes with the validity window
// removed. Everything that identifies one launch (generation, nonce, services,
// artifact digests) stays, so the bytes are identical across renewals of the
// same launch. Callers use them as the secret-channel context; it does not
// validate the manifest.
func (m Manifest) AuthorityBytes() ([]byte, error) {
	m.IssuedAt = 0
	m.ExpiresAt = 0
	return m.canonicalBytesUnchecked()
}

// AuthorityDigest is the sha256 of AuthorityBytes for a structurally valid
// manifest. Ownership labels use it so a renewal never changes them.
func (m Manifest) AuthorityDigest() ([32]byte, error) {
	var zero [32]byte
	if err := m.Validate(); err != nil {
		return zero, err
	}
	b, err := m.AuthorityBytes()
	if err != nil {
		return zero, err
	}
	return sha256.Sum256(b), nil
}

// RenewManifest returns base with a fresh validity window starting at now.
// Only IssuedAt and ExpiresAt change.
func RenewManifest(base Manifest, now time.Time, ttl time.Duration) (Manifest, error) {
	if err := base.Validate(); err != nil {
		return Manifest{}, err
	}
	if ttl < time.Second || ttl > MaxManifestTTL {
		return Manifest{}, fail(ErrTTL)
	}
	renewed := base
	renewed.IssuedAt = now.Unix()
	renewed.ExpiresAt = now.Add(ttl).Unix()
	if err := renewed.Validate(); err != nil {
		return Manifest{}, err
	}
	return renewed, nil
}

// AcceptRenewal decides whether candidate may replace current. It must be live
// at now, carry the identical launch authority, and never end earlier than the
// manifest it replaces. Re-presenting the current manifest is accepted so a
// reload that finds nothing new is not an error.
func AcceptRenewal(current, candidate Manifest, now time.Time) error {
	if err := candidate.ValidateAt(now); err != nil {
		return err
	}
	want, err := current.AuthorityDigest()
	if err != nil {
		return err
	}
	got, err := candidate.AuthorityDigest()
	if err != nil {
		return err
	}
	if got != want {
		return fail(ErrBinding)
	}
	if candidate.ExpiresAt < current.ExpiresAt {
		return fail(ErrReplay)
	}
	return nil
}

// RenewSignedManifest verifies a previously signed template against the trust
// policy (ignoring the template's own validity window), refuses to renew a
// template older than maxAge (itself capped at MaxRenewalAge), and returns the
// same launch authority signed again with a fresh window. The private key must
// belong to the template's trusted key ID.
//
// The age is measured from the template's own issued_at and each renewal sets a
// new issued_at. A template that is itself the output of earlier renewals
// therefore never ages out, so callers must keep the template in a place that
// nothing re-signs.
func RenewSignedManifest(
	template []byte,
	policy TrustPolicy,
	private ed25519.PrivateKey,
	now time.Time,
	ttl, maxAge time.Duration,
) ([]byte, error) {
	if maxAge <= 0 || maxAge > MaxRenewalAge || len(private) != ed25519.PrivateKeySize {
		return nil, fail(ErrInvalidInput)
	}
	signed, err := ParseSignedManifest(template)
	if err != nil {
		return nil, err
	}
	signature, err := base64.StdEncoding.DecodeString(signed.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return nil, fail(ErrSignature)
	}
	if err := verifyManifestTrust(signed.Manifest, signature, signed.KeyID, policy); err != nil {
		return nil, err
	}
	public, _ := private.Public().(ed25519.PublicKey)
	if !bytes.Equal(public, policy.AllowedSigningKeys[signed.KeyID]) {
		return nil, fail(ErrSignature)
	}
	issued := time.Unix(signed.Manifest.IssuedAt, 0)
	if now.Before(issued) {
		return nil, fail(ErrNotYetValid)
	}
	if now.Sub(issued) > maxAge {
		return nil, fail(ErrExpired)
	}
	renewed, err := RenewManifest(signed.Manifest, now, ttl)
	if err != nil {
		return nil, err
	}
	return SignManifest(renewed, signed.KeyID, private, now)
}
