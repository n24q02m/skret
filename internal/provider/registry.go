package provider

import (
	"fmt"
	"sort"
	"sync"

	"github.com/n24q02m/skret/internal/config"
)

// Factory creates a SecretProvider from resolved config.
type Factory func(cfg *config.ResolvedConfig) (SecretProvider, error)

// Registry maps provider names to factories.
type Registry struct {
	mu        sync.RWMutex
	factories map[string]Factory
}

// NewRegistry creates an empty provider registry.
func NewRegistry() *Registry {
	return &Registry{factories: make(map[string]Factory)}
}

// Register adds a provider factory under the given name.
func (r *Registry) Register(name string, factory Factory) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.factories[name] = factory
}

// New creates a provider instance by name.
func (r *Registry) New(name string, cfg *config.ResolvedConfig) (SecretProvider, error) {
	r.mu.RLock()
	factory, ok := r.factories[name]
	r.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("provider: unknown provider %q (available: %v)", name, r.Providers())
	}
	return factory(cfg)
}

// Providers returns sorted list of registered provider names.
func (r *Registry) Providers() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.factories))
	for name := range r.factories {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
