package provider

import (
	"context"
	"errors"
	"time"
)

var (
	ErrNotFound               = errors.New("secret not found")
	ErrCapabilityNotSupported = errors.New("provider does not support this operation")
)

// Secret holds a secret key-value pair with metadata.
type Secret struct {
	Key     string
	Value   string
	Version int64
	Meta    SecretMeta
}

// SecretMeta holds optional metadata about a secret.
type SecretMeta struct {
	Description string
	Tags        map[string]string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	CreatedBy   string
}

// Capabilities describes what a provider supports.
type Capabilities struct {
	Write      bool
	Versioning bool
	Tagging    bool
	Rotation   bool
	AuditLog   bool
	MaxValueKB int
}

// SecretProvider is the core abstraction for all secret backends.
type SecretProvider interface {
	Name() string
	Capabilities() Capabilities

	Get(ctx context.Context, key string) (*Secret, error)
	List(ctx context.Context, pathPrefix string) ([]*Secret, error)

	Set(ctx context.Context, key string, value string, meta SecretMeta) error
	Delete(ctx context.Context, key string) error

	Close() error
}
