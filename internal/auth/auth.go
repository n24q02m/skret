// Package auth provides native authentication flows for skret-supported
// secret backends (AWS, Doppler, Infisical) with zero external CLI deps.
package auth

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ErrCredentialNotFound is returned when a credential is absent from the store.
var ErrCredentialNotFound = errors.New("auth: credential not found")

// ErrAuthMethodUnsupported is returned when a provider does not support the named method.
var ErrAuthMethodUnsupported = errors.New("auth: method not supported")

// Credential represents a single provider's authentication state.
type Credential struct {
	Provider  string            `yaml:"-"`
	Method    string            `yaml:"method"`
	Token     string            `yaml:"token,omitempty"`
	ExpiresAt time.Time         `yaml:"expires_at,omitempty"`
	Metadata  map[string]string `yaml:"metadata,omitempty"`
}

// IsExpired checks if the credential has a non-zero expiry that is past.
func (c *Credential) IsExpired() bool {
	if c.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(c.ExpiresAt)
}

// Method describes one authentication path exposed by a provider.
type Method struct {
	Name        string
	Description string
	Interactive bool
}

// Provider is the interface each backend implements.
type Provider interface {
	Name() string
	Methods() []Method
	Login(ctx context.Context, method string, opts map[string]string) (*Credential, error)
	Validate(ctx context.Context, cred *Credential) error
	Logout(ctx context.Context) error
}

// registry maps provider names to their implementations.
var registry = map[string]Provider{}

// Register adds a provider to the global registry.
func Register(name string, p Provider) {
	registry[name] = p
}

// Resolve returns the stored credential for a provider, performing validation
// if the credential exists. Returns ErrCredentialNotFound if not stored.
func Resolve(ctx context.Context, providerName string) (*Credential, error) {
	store := NewStore()
	cred, err := store.Load(providerName)
	if err != nil {
		return nil, err
	}
	if cred.IsExpired() {
		return nil, fmt.Errorf("auth: %s credential expired at %s", providerName, cred.ExpiresAt.Format(time.RFC3339))
	}
	return cred, nil
}

// Login performs interactive login for a provider using the given method.
func Login(ctx context.Context, providerName string, opts map[string]string) error {
	p, ok := registry[providerName]
	if !ok {
		return fmt.Errorf("auth: unknown provider %q", providerName)
	}

	method := ""
	if opts != nil {
		method = opts["method"]
	}
	if method == "" && len(p.Methods()) == 1 {
		method = p.Methods()[0].Name
	}

	cred, err := p.Login(ctx, method, opts)
	if err != nil {
		return fmt.Errorf("auth %s: login: %w", providerName, err)
	}
	cred.Provider = providerName

	store := NewStore()
	return store.Save(cred)
}
