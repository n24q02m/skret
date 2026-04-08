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
	names := make([]string, 0, len(r.constructors))
	for name := range r.constructors {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
