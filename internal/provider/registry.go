package provider

import (
	"fmt"
	"sort"
	"sync"

	"github.com/n24q02m/skret/internal/config"
)

// Constructor creates a SecretProvider from resolved config.
type Constructor func(cfg *config.ResolvedConfig) (SecretProvider, error)

// Registry maps provider names to constructors.
type Registry struct {
	mu           sync.RWMutex
	constructors map[string]Constructor
	names        []string
}

// NewRegistry creates an empty provider registry.
func NewRegistry() *Registry {
	return &Registry{constructors: make(map[string]Constructor)}
}

// Register adds a provider constructor under the given name.
func (r *Registry) Register(name string, ctor Constructor) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.constructors[name] = ctor

	// Rebuild names cache
	r.names = make([]string, 0, len(r.constructors))
	for n := range r.constructors {
		r.names = append(r.names, n)
	}
	sort.Strings(r.names)
}

// New creates a provider instance by name.
func (r *Registry) New(name string, cfg *config.ResolvedConfig) (SecretProvider, error) {
	r.mu.RLock()
	ctor, ok := r.constructors[name]
	r.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("provider: unknown provider %q (available: %v)", name, r.Providers())
	}
	return ctor(cfg)
}

// Providers returns sorted list of registered provider names.
func (r *Registry) Providers() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Return a copy to avoid external modifications to the cache
	names := make([]string, len(r.names))
	copy(names, r.names)
	return names
}
