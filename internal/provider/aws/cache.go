package aws

import (
	"sync"

	"github.com/n24q02m/skret/internal/provider"
)

// versionCache is an in-process cache of resolved parameter values keyed by
// parameter name and the SSM version the value was read at. SSM parameters
// are immutable per version, so a cached (name, VersionId) pair can be
// served without an API call for as long as the process trusts its own
// snapshot. Mutations issued through the same Provider (Set/Delete, and
// Rollback which routes through Set) invalidate the affected key, keeping
// the cache coherent with everything skret itself did; changes made by
// other processes are observed on the next process lifetime, which is the
// documented semantics of an in-process cache.
//
// Scope: only the on-demand read paths (Get, GetVersion, GetBatch) consult
// the cache. List/ListNames/Fingerprint stay live on every call because
// `run --watch` relies on them to detect external changes.
type versionCache struct {
	mu    sync.RWMutex
	items map[string]*provider.Secret
}

func newVersionCache() *versionCache {
	return &versionCache{items: make(map[string]*provider.Secret)}
}

// getLatest returns the cached secret for key regardless of version.
// version <= 0 means "latest read" semantics (Get path); a cached entry
// always matches.
func (c *versionCache) getLatest(key string) (*provider.Secret, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	s, ok := c.items[key]
	if !ok {
		return nil, false
	}
	cp := *s
	return &cp, true
}

// getVersion returns the cached secret for key only when it was read at
// exactly the requested version (GetVersion path).
func (c *versionCache) getVersion(key string, version int64) (*provider.Secret, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	s, ok := c.items[key]
	if !ok || s.Version != version {
		return nil, false
	}
	cp := *s
	return &cp, true
}

// put stores a copy of the secret under its parameter name. The stored copy
// is detached from the caller's struct so later caller mutations (e.g. ${KEY}
// reference resolution) cannot corrupt the cache.
func (c *versionCache) put(s *provider.Secret) {
	if s == nil || s.Key == "" {
		return
	}
	cp := *s
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[s.Key] = &cp
}

// invalidate drops one key after a successful or possibly-committed mutation.
func (c *versionCache) invalidate(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.items, key)
}
