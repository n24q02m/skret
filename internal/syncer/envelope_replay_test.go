package syncer

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyAndConsumeSignedEnvelope_AcceptsValidEnvelopeOnce(t *testing.T) {
	now := replayTestTime()
	publicKey, privateKey := replayTestKeys(t)
	envelope := mustReplayEnvelope(t, privateKey, "operator", "hub", "nonce-once", now.Add(5*time.Minute), []byte("payload"))
	store := NewInMemoryEnvelopeReplayStore(8)

	require.NoError(t, VerifyAndConsumeSignedEnvelope(envelope, publicKey, now, store))
	require.ErrorIs(t, VerifyAndConsumeSignedEnvelope(envelope, publicKey, now, store), ErrEnvelopeReplay)
	assert.Equal(t, 1, store.Len())
}

func TestVerifyAndConsumeSignedEnvelope_RejectsSameScopeNonceAcrossEnvelopeChanges(t *testing.T) {
	now := replayTestTime()
	publicKey, privateKey := replayTestKeys(t)
	store := NewInMemoryEnvelopeReplayStore(8)

	first := mustReplayEnvelope(t, privateKey, "operator", "hub", "nonce-stable", now.Add(5*time.Minute), []byte("first"))
	require.NoError(t, VerifyAndConsumeSignedEnvelope(first, publicKey, now, store))

	changedBody := mustReplayEnvelope(t, privateKey, "operator", "hub", "nonce-stable", now.Add(5*time.Minute), []byte("second"))
	require.ErrorIs(t, VerifyAndConsumeSignedEnvelope(changedBody, publicKey, now, store), ErrEnvelopeReplay)

	changedExpiry := mustReplayEnvelope(t, privateKey, "operator", "hub", "nonce-stable", now.Add(6*time.Minute), []byte("first"))
	require.ErrorIs(t, VerifyAndConsumeSignedEnvelope(changedExpiry, publicKey, now, store), ErrEnvelopeReplay)

	changedSignature := mustReplayEnvelope(t, privateKey, "operator", "hub", "nonce-stable", now.Add(7*time.Minute), []byte("first"))
	require.NotEqual(t, first.Signature, changedSignature.Signature)
	require.ErrorIs(t, VerifyAndConsumeSignedEnvelope(changedSignature, publicKey, now, store), ErrEnvelopeReplay)
}

func TestVerifyAndConsumeSignedEnvelope_BadSignatureAndExpiryDoNotConsume(t *testing.T) {
	now := replayTestTime()
	publicKey, privateKey := replayTestKeys(t)

	t.Run("bad signature", func(t *testing.T) {
		store := NewInMemoryEnvelopeReplayStore(8)
		envelope := mustReplayEnvelope(t, privateKey, "operator", "hub", "nonce-bad-signature", now.Add(time.Minute), []byte("payload"))
		invalid := *envelope
		invalid.Signature = append([]byte(nil), envelope.Signature...)
		invalid.Signature[0] ^= 0xff

		require.Error(t, VerifyAndConsumeSignedEnvelope(&invalid, publicKey, now, store))
		require.NoError(t, VerifyAndConsumeSignedEnvelope(envelope, publicKey, now, store))
	})

	t.Run("expired envelope", func(t *testing.T) {
		store := NewInMemoryEnvelopeReplayStore(8)
		envelope := mustReplayEnvelope(t, privateKey, "operator", "hub", "nonce-expired", now.Add(time.Minute), []byte("payload"))

		require.Error(t, VerifyAndConsumeSignedEnvelope(envelope, publicKey, now.Add(2*time.Minute), store))
		require.NoError(t, VerifyAndConsumeSignedEnvelope(envelope, publicKey, now.Add(30*time.Second), store))
	})
}

func TestVerifyAndConsumeSignedEnvelope_ConcurrentCallsHaveOneWinner(t *testing.T) {
	now := replayTestTime()
	publicKey, privateKey := replayTestKeys(t)
	envelope := mustReplayEnvelope(t, privateKey, "operator", "hub", "nonce-concurrent", now.Add(5*time.Minute), []byte("payload"))
	store := NewInMemoryEnvelopeReplayStore(8)

	const callers = 32
	start := make(chan struct{})
	var ready sync.WaitGroup
	var done sync.WaitGroup
	errs := make(chan error, callers)
	ready.Add(callers)
	done.Add(callers)
	for range callers {
		go func() {
			defer done.Done()
			ready.Done()
			<-start
			errs <- VerifyAndConsumeSignedEnvelope(envelope, publicKey, now, store)
		}()
	}
	ready.Wait()
	close(start)
	done.Wait()
	close(errs)

	winners := 0
	replays := 0
	for err := range errs {
		switch {
		case err == nil:
			winners++
		case errors.Is(err, ErrEnvelopeReplay):
			replays++
		default:
			t.Fatalf("unexpected concurrent verification error: %v", err)
		}
	}
	assert.Equal(t, 1, winners)
	assert.Equal(t, callers-1, replays)
	assert.Equal(t, 1, store.Len())
}

func TestEnvelopeReplayStore_CleansExpiredEntriesAndBoundsCapacity(t *testing.T) {
	now := replayTestTime()
	publicKey, privateKey := replayTestKeys(t)
	store := NewInMemoryEnvelopeReplayStore(2)

	first := mustReplayEnvelope(t, privateKey, "operator", "hub", "nonce-expiring", now.Add(time.Minute), []byte("first"))
	second := mustReplayEnvelope(t, privateKey, "operator", "hub", "nonce-active", now.Add(5*time.Minute), []byte("second"))
	third := mustReplayEnvelope(t, privateKey, "operator", "hub", "nonce-third", now.Add(5*time.Minute), []byte("third"))
	fourth := mustReplayEnvelope(t, privateKey, "operator", "hub", "nonce-fourth", now.Add(5*time.Minute), []byte("fourth"))

	require.NoError(t, VerifyAndConsumeSignedEnvelope(first, publicKey, now, store))
	require.NoError(t, VerifyAndConsumeSignedEnvelope(second, publicKey, now, store))
	require.ErrorIs(t, VerifyAndConsumeSignedEnvelope(third, publicKey, now, store), ErrEnvelopeReplayStoreFull)

	cleanupNow := now.Add(2 * time.Minute)
	require.NoError(t, VerifyAndConsumeSignedEnvelope(third, publicKey, cleanupNow, store))
	assert.Equal(t, 2, store.Len(), "expired entries must be removed before bounded admission")
	require.ErrorIs(t, VerifyAndConsumeSignedEnvelope(fourth, publicKey, cleanupNow, store), ErrEnvelopeReplayStoreFull)
	assert.LessOrEqual(t, store.Len(), 2)
}

func TestVerifyAndConsumeSignedEnvelope_UsesCanonicalDigestAndScope(t *testing.T) {
	now := replayTestTime()
	publicKey, privateKey := replayTestKeys(t)
	envelope := mustReplayEnvelope(t, privateKey, "operator", "hub", "nonce-canonical", now.Add(time.Minute), []byte("payload"))
	store := &recordingReplayStore{}

	require.NoError(t, VerifyAndConsumeSignedEnvelope(envelope, publicKey, now, store))
	canonical, err := envelope.CanonicalSigningBytes()
	require.NoError(t, err)
	assert.Equal(t, digestBytes(canonical), store.digest)
	assert.Equal(t, EnvelopeReplayScope{Audience: envelope.Audience, Role: envelope.Role, Nonce: envelope.Nonce}, store.scope)
}

func TestVerifyAndConsumeSignedEnvelope_AllowsDifferentScopesAndNonces(t *testing.T) {
	now := replayTestTime()
	publicKey, privateKey := replayTestKeys(t)
	store := NewInMemoryEnvelopeReplayStore(8)

	base := mustReplayEnvelope(t, privateKey, "operator", "hub", "nonce-shared", now.Add(5*time.Minute), []byte("payload"))
	otherRole := mustReplayEnvelope(t, privateKey, "auditor", "hub", "nonce-shared", now.Add(5*time.Minute), []byte("payload"))
	otherAudience := mustReplayEnvelope(t, privateKey, "operator", "worker", "nonce-shared", now.Add(5*time.Minute), []byte("payload"))
	otherNonce := mustReplayEnvelope(t, privateKey, "operator", "hub", "nonce-other", now.Add(5*time.Minute), []byte("payload"))

	require.NoError(t, VerifyAndConsumeSignedEnvelope(base, publicKey, now, store))
	require.NoError(t, VerifyAndConsumeSignedEnvelope(otherRole, publicKey, now, store))
	require.NoError(t, VerifyAndConsumeSignedEnvelope(otherAudience, publicKey, now, store))
	require.NoError(t, VerifyAndConsumeSignedEnvelope(otherNonce, publicKey, now, store))
	assert.Equal(t, 4, store.Len())
}

func TestVerifyAndConsumeSignedEnvelope_ReturnsValueFreeErrors(t *testing.T) {
	now := replayTestTime()
	publicKey, privateKey := replayTestKeys(t)
	secret := "nonce-secret-body-secret-role-secret-audience"
	envelope := mustReplayEnvelope(t, privateKey, "role-"+secret, "audience-"+secret, "nonce-"+secret, now.Add(time.Minute), []byte(secret))

	invalid := *envelope
	invalid.Signature = append([]byte(nil), envelope.Signature...)
	invalid.Signature[0] ^= 0xff
	err := VerifyAndConsumeSignedEnvelope(&invalid, publicKey, now, NewInMemoryEnvelopeReplayStore(8))
	require.Error(t, err)
	assert.NotContains(t, err.Error(), secret)

	err = VerifyAndConsumeSignedEnvelope(envelope, publicKey, now, replayErrorStore{err: errors.New("store leaked " + secret)})
	require.ErrorIs(t, err, ErrEnvelopeReplayStoreUnavailable)
	assert.NotContains(t, err.Error(), secret)
}

type recordingReplayStore struct {
	scope  EnvelopeReplayScope
	digest string
}

func (s *recordingReplayStore) Consume(scope EnvelopeReplayScope, digest string, expiresAt, now time.Time) (bool, error) {
	s.scope = scope
	s.digest = digest
	return true, nil
}

type replayErrorStore struct {
	err error
}

func (s replayErrorStore) Consume(EnvelopeReplayScope, string, time.Time, time.Time) (bool, error) {
	return false, s.err
}

func replayTestTime() time.Time {
	return time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
}

func replayTestKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return publicKey, privateKey
}

func mustReplayEnvelope(t *testing.T, signer ed25519.PrivateKey, role, audience, nonce string, expiresAt time.Time, body []byte) *ExecutorEnvelope {
	t.Helper()
	envelope, err := BuildSignedEnvelope("sha256:"+strings.Repeat("a", 64), role, audience, nonce, expiresAt, body, signer, replayTestTime())
	require.NoError(t, err)
	return envelope
}
