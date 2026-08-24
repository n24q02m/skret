package syncer

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnvelopeReplayStore_RejectsUnavailableInvalidAndExpiredRequests(t *testing.T) {
	now := replayTestTime()
	scope := EnvelopeReplayScope{Audience: "hub", Role: "operator", Nonce: "nonce"}
	digest := "sha256:" + strings.Repeat("a", 64)

	var nilStore *InMemoryEnvelopeReplayStore
	consumed, err := nilStore.Consume(scope, digest, now.Add(time.Minute), now)
	assert.False(t, consumed)
	require.ErrorIs(t, err, ErrEnvelopeReplayStoreUnavailable)
	assert.Equal(t, 0, nilStore.Len())

	store := &InMemoryEnvelopeReplayStore{}
	invalidScopes := []EnvelopeReplayScope{
		{Role: "operator", Nonce: "nonce"},
		{Audience: "hub", Nonce: "nonce"},
		{Audience: "hub", Role: "operator"},
	}
	for _, invalidScope := range invalidScopes {
		consumed, err := store.Consume(invalidScope, digest, now.Add(time.Minute), now)
		assert.False(t, consumed)
		require.ErrorIs(t, err, errEnvelopeReplayRequest)
	}

	consumed, err = store.Consume(scope, "not-a-digest", now.Add(time.Minute), now)
	assert.False(t, consumed)
	require.ErrorIs(t, err, errEnvelopeReplayRequest)
	consumed, err = store.Consume(scope, digest, time.Time{}, now)
	assert.False(t, consumed)
	require.ErrorIs(t, err, errEnvelopeReplayExpired)
	consumed, err = store.Consume(scope, digest, now, now)
	assert.False(t, consumed)
	require.ErrorIs(t, err, errEnvelopeReplayExpired)
	assert.Equal(t, 0, store.Len())
}

func TestEnvelopeReplayStore_InitializesDefaultsAndRejectsReplayRegardlessOfDigest(t *testing.T) {
	now := replayTestTime()
	scope := EnvelopeReplayScope{Audience: "hub", Role: "operator", Nonce: "nonce"}
	digest := "sha256:" + strings.Repeat("b", 64)

	defaultStore := NewInMemoryEnvelopeReplayStore()
	require.NotNil(t, defaultStore)
	assert.Equal(t, defaultEnvelopeReplayStoreCapacity, defaultStore.capacity)
	negativeStore := NewInMemoryEnvelopeReplayStore(-1)
	assert.Equal(t, defaultEnvelopeReplayStoreCapacity, negativeStore.capacity)
	customStore := NewInMemoryEnvelopeReplayStore(1)
	assert.Equal(t, 1, customStore.capacity)

	consumed, err := defaultStore.Consume(scope, digest, now.Add(time.Minute), now)
	require.NoError(t, err)
	assert.True(t, consumed)
	consumed, err = defaultStore.Consume(scope, "sha256:"+strings.Repeat("c", 64), now.Add(2*time.Minute), now)
	require.NoError(t, err)
	assert.False(t, consumed)
	assert.Equal(t, 1, defaultStore.Len())
}

func TestVerifyAndConsumeSignedEnvelope_RejectsNilStoreAndMapsStoreErrors(t *testing.T) {
	now := replayTestTime()
	publicKey, privateKey := replayTestKeys(t)
	envelope := mustReplayEnvelope(t, privateKey, "operator", "hub", "nonce-store-errors", now.Add(time.Minute), []byte("payload"))

	require.ErrorIs(t, VerifyAndConsumeSignedEnvelope(envelope, publicKey, now, nil), ErrEnvelopeReplayStoreUnavailable)
	require.ErrorContains(t, VerifyAndConsumeSignedEnvelope(envelope, []byte("short"), now, NewInMemoryEnvelopeReplayStore()), "invalid verifier key")

	require.ErrorIs(t, VerifyAndConsumeSignedEnvelope(envelope, publicKey, now, replayErrorStore{err: ErrEnvelopeReplayStoreFull}), ErrEnvelopeReplayStoreFull)
	require.ErrorIs(t, VerifyAndConsumeSignedEnvelope(envelope, publicKey, now, replayErrorStore{err: errors.New("store contains payload")}), ErrEnvelopeReplayStoreUnavailable)

	invalid := *envelope
	invalid.Signature = append([]byte(nil), envelope.Signature...)
	invalid.Signature[0] ^= 1
	recording := &recordingReplayStore{}
	require.Error(t, VerifyAndConsumeSignedEnvelope(&invalid, publicKey, now, recording))
	assert.Empty(t, recording.digest, "invalid envelopes must never reach replay authority")
}
