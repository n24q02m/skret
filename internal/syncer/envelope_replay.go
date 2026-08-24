package syncer

import (
	"crypto/ed25519"
	"errors"
	"sync"
	"time"
)

const defaultEnvelopeReplayStoreCapacity = 1024

var (
	// ErrEnvelopeReplay means the scope's nonce was already consumed while it
	// was still valid. It deliberately does not include any envelope values.
	ErrEnvelopeReplay = errors.New("envelope: replay detected")

	// ErrEnvelopeReplayStoreFull means the bounded in-memory store cannot admit
	// another unexpired scope without evicting replay authority.
	ErrEnvelopeReplayStoreFull = errors.New("envelope: replay store capacity exceeded")

	// ErrEnvelopeReplayStoreUnavailable means the verifier could not ask its
	// replay authority to consume the scope. It deliberately hides store errors.
	ErrEnvelopeReplayStoreUnavailable = errors.New("envelope: replay store unavailable")

	errEnvelopeReplayRequest   = errors.New("envelope: invalid replay request")
	errEnvelopeReplayExpired   = errors.New("envelope: replay request expired")
	errEnvelopeReplayCanonical = errors.New("envelope: canonical digest failed")
)

// EnvelopeReplayScope identifies the namespace in which a nonce is single-use.
// A nonce may be reused by a different audience or role; the full scope is
// included in the signed canonical envelope fields.
type EnvelopeReplayScope struct {
	Audience string
	Role     string
	Nonce    string
}

// EnvelopeReplayStore atomically consumes one signed envelope scope. digest is
// the SHA-256 digest of canonical signing bytes (without the detached
// signature). Implementations must retain an unexpired scope and reject a
// second consume of that scope, regardless of a later digest.
type EnvelopeReplayStore interface {
	Consume(scope EnvelopeReplayScope, digest string, expiresAt, now time.Time) (bool, error)
}

// InMemoryEnvelopeReplayStore is a concurrency-safe, bounded replay authority
// for deterministic source-level tests. It is not durable executor storage.
type InMemoryEnvelopeReplayStore struct {
	mu       sync.Mutex
	entries  map[EnvelopeReplayScope]envelopeReplayEntry
	capacity int
}

type envelopeReplayEntry struct {
	digest    string
	expiresAt time.Time
}

// NewInMemoryEnvelopeReplayStore creates a bounded in-memory replay store. A
// missing or non-positive capacity selects the conservative default.
func NewInMemoryEnvelopeReplayStore(capacity ...int) *InMemoryEnvelopeReplayStore {
	maxEntries := defaultEnvelopeReplayStoreCapacity
	if len(capacity) > 0 && capacity[0] > 0 {
		maxEntries = capacity[0]
	}
	return &InMemoryEnvelopeReplayStore{
		entries:  make(map[EnvelopeReplayScope]envelopeReplayEntry),
		capacity: maxEntries,
	}
}

// Len reports the number of retained scopes. Expired entries are removed on
// the next consume; callers should use Consume for clock-driven cleanup.
func (s *InMemoryEnvelopeReplayStore) Len() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureInitializedLocked()
	return len(s.entries)
}

// Consume atomically accepts a new unexpired scope or reports a replay. It
// cleans expired entries before enforcing capacity so stale state cannot grow
// without bound or block fresh valid scopes forever.
func (s *InMemoryEnvelopeReplayStore) Consume(scope EnvelopeReplayScope, digest string, expiresAt, now time.Time) (bool, error) {
	if s == nil {
		return false, ErrEnvelopeReplayStoreUnavailable
	}
	if err := validateEnvelopeReplayScope(scope); err != nil {
		return false, err
	}
	if !validDigest(digest) {
		return false, errEnvelopeReplayRequest
	}
	if expiresAt.IsZero() || !expiresAt.After(now) {
		return false, errEnvelopeReplayExpired
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureInitializedLocked()
	s.cleanupExpiredLocked(now)

	if _, exists := s.entries[scope]; exists {
		return false, nil
	}
	if len(s.entries) >= s.capacity {
		return false, ErrEnvelopeReplayStoreFull
	}
	s.entries[scope] = envelopeReplayEntry{digest: digest, expiresAt: expiresAt}
	return true, nil
}

func (s *InMemoryEnvelopeReplayStore) ensureInitializedLocked() {
	if s.entries == nil {
		s.entries = make(map[EnvelopeReplayScope]envelopeReplayEntry)
	}
	if s.capacity <= 0 {
		s.capacity = defaultEnvelopeReplayStoreCapacity
	}
}

func (s *InMemoryEnvelopeReplayStore) cleanupExpiredLocked(now time.Time) {
	for scope, entry := range s.entries {
		if !entry.expiresAt.After(now) {
			delete(s.entries, scope)
		}
	}
}

func validateEnvelopeReplayScope(scope EnvelopeReplayScope) error {
	if err := validateRequiredField(scope.Audience, "audience"); err != nil {
		return errEnvelopeReplayRequest
	}
	if err := validateRequiredField(scope.Role, "role"); err != nil {
		return errEnvelopeReplayRequest
	}
	if err := validateRequiredField(scope.Nonce, "nonce"); err != nil {
		return errEnvelopeReplayRequest
	}
	return nil
}

// VerifyAndConsumeSignedEnvelope verifies all existing envelope bindings before
// atomically consuming its audience/role/nonce scope. Invalid, tampered, and
// expired envelopes never reach the replay store.
func VerifyAndConsumeSignedEnvelope(envelope *ExecutorEnvelope, publicKey ed25519.PublicKey, now time.Time, store EnvelopeReplayStore) error {
	if err := VerifySignedEnvelope(envelope, publicKey, now); err != nil {
		return err
	}
	if store == nil {
		return ErrEnvelopeReplayStoreUnavailable
	}

	canonical, err := envelope.CanonicalSigningBytes()
	if err != nil {
		return errEnvelopeReplayCanonical
	}
	digest := digestBytes(canonical)
	scope := EnvelopeReplayScope{
		Audience: envelope.Audience,
		Role:     envelope.Role,
		Nonce:    envelope.Nonce,
	}
	consumed, err := store.Consume(scope, digest, envelope.ExpiresAt, now)
	if err != nil {
		if errors.Is(err, ErrEnvelopeReplayStoreFull) {
			return ErrEnvelopeReplayStoreFull
		}
		return ErrEnvelopeReplayStoreUnavailable
	}
	if !consumed {
		return ErrEnvelopeReplay
	}
	return nil
}
