package secretlaunch

import (
	"context"
	"strconv"

	skprovider "github.com/n24q02m/skret/internal/provider"
)

// SecretProvider is deliberately narrower than the general skret provider
// interface. A launch can ask only for an exact key and exact provider version.
type SecretProvider interface {
	Fetch(ctx context.Context, key, version string) ([]byte, error)
}

type FetchFunc func(context.Context, string, string) ([]byte, error)

func (f FetchFunc) Fetch(ctx context.Context, key, version string) ([]byte, error) {
	if f == nil {
		return nil, fail(ErrNoProvider)
	}
	return f(ctx, key, version)
}

// SkretProvider adapts the general provider surface to immutable launch reads.
// Providers without exact-version support are rejected before any latest-value
// fallback can occur.
type SkretProvider struct {
	Provider skprovider.SecretProvider
}

func NewSkretProvider(provider skprovider.SecretProvider) (*SkretProvider, error) {
	if provider == nil {
		return nil, fail(ErrNoProvider)
	}
	if _, ok := provider.(skprovider.VersionedReader); !ok {
		return nil, fail(ErrNoProvider)
	}
	return &SkretProvider{Provider: provider}, nil
}

func (p *SkretProvider) Fetch(ctx context.Context, key, version string) ([]byte, error) {
	if p == nil || p.Provider == nil || !validKeyName(key) || !validProviderVersion(version) {
		return nil, fail(ErrFetch)
	}
	numeric, _ := strconv.ParseInt(version, 10, 64)
	reader, ok := p.Provider.(skprovider.VersionedReader)
	if !ok {
		return nil, fail(ErrNoProvider)
	}
	secret, err := reader.GetVersion(ctx, key, numeric)
	if err != nil || secret == nil || secret.Version != numeric || secret.Key != key {
		return nil, fail(ErrFetch)
	}
	return []byte(secret.Value), nil
}

type SecretBuffer struct {
	Key     string
	Version string
	Env     string
	Bytes   []byte
}

type SecretSet struct {
	items map[string]SecretBuffer
}

func (s SecretSet) Len() int { return len(s.items) }

func (s SecretSet) Get(key string) (SecretBuffer, bool) {
	item, ok := s.items[key]
	if !ok {
		return SecretBuffer{}, false
	}
	item.Bytes = append([]byte(nil), item.Bytes...)
	return item, true
}

func (s SecretSet) Zeroize() {
	for key, item := range s.items {
		Zeroize(item.Bytes)
		item.Bytes = nil
		s.items[key] = item
	}
	s.items = nil
}

func (s SecretSet) names() []string {
	result := make([]string, 0, len(s.items))
	for key := range s.items {
		result = append(result, key)
	}
	return result
}

func FetchSecrets(ctx context.Context, provider SecretProvider, keys []ManifestKey) (SecretSet, error) {
	if provider == nil || len(keys) == 0 {
		return SecretSet{}, fail(ErrNoProvider)
	}
	result := SecretSet{items: make(map[string]SecretBuffer, len(keys))}
	for _, requested := range keys {
		if !validKeyName(requested.Name) || !validProviderVersion(requested.Version) ||
			!validEnvName(requested.Env) {
			result.Zeroize()
			return SecretSet{}, failKey(ErrKey, requested.Name)
		}
		if _, exists := result.items[requested.Name]; exists {
			result.Zeroize()
			return SecretSet{}, failKey(ErrKey, requested.Name)
		}
		value, err := provider.Fetch(ctx, requested.Name, requested.Version)
		if err != nil || value == nil || len(value) > MaxValueLength {
			Zeroize(value)
			result.Zeroize()
			return SecretSet{}, failKey(ErrFetch, requested.Name)
		}
		result.items[requested.Name] = SecretBuffer{
			Key:     requested.Name,
			Version: requested.Version,
			Env:     requested.Env,
			Bytes:   value,
		}
	}
	return result, nil
}
