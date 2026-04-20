---
title: Adding a Provider
description: "Guide for implementing a new `SecretProvider` backend."
---

Guide for implementing a new `SecretProvider` backend.

## 1. Implement the Interface

Create a new package under `internal/provider/<name>/`:

```
internal/provider/gcp/
  gcp.go       -- Provider implementation
  auth.go      -- Credential helpers (if needed)
  errors.go    -- Error translation (if needed)
```

Implement the `SecretProvider` interface from `internal/provider/provider.go`:

```go
package gcp

import (
    "context"
    "github.com/n24q02m/skret/internal/config"
    "github.com/n24q02m/skret/internal/provider"
)

type Provider struct {
    // Client, config, etc.
}

func New(cfg *config.ResolvedConfig) (*Provider, error) {
    // Initialize the provider using cfg.Path, cfg.Region, etc.
    return &Provider{}, nil
}

func (p *Provider) Name() string                                { return "gcp" }
func (p *Provider) Capabilities() provider.Capabilities         { /* ... */ }
func (p *Provider) Get(ctx context.Context, key string) (*provider.Secret, error) { /* ... */ }
func (p *Provider) List(ctx context.Context, prefix string) ([]*provider.Secret, error) { /* ... */ }
func (p *Provider) Set(ctx context.Context, key, value string, meta provider.SecretMeta) error { /* ... */ }
func (p *Provider) Delete(ctx context.Context, key string) error { /* ... */ }
func (p *Provider) GetHistory(ctx context.Context, key string) ([]*provider.Secret, error) { /* ... */ }
func (p *Provider) Rollback(ctx context.Context, key string, version int64) error { /* ... */ }
func (p *Provider) Close() error { /* ... */ }
```

## 2. Register in the Registry

Add the provider constructor in two places:

**`internal/cli/root.go`** (CLI usage):

```go
import "github.com/n24q02m/skret/internal/provider/gcp"

reg.Register("gcp", func(c *config.ResolvedConfig) (provider.SecretProvider, error) {
    return gcp.New(c)
})
```

**`pkg/skret/client.go`** (library usage):

```go
import "github.com/n24q02m/skret/internal/provider/gcp"

reg.Register("gcp", func(c *config.ResolvedConfig) (provider.SecretProvider, error) {
    return gcp.New(c)
})
```

## 3. Add Config Validation

Update `internal/config/schema.go` to validate provider-specific fields:

```go
case "gcp":
    if e.Path == "" {
        return fmt.Errorf("config: environment %q: path is required for gcp provider", name)
    }
```

Add any new fields to the `Environment` struct if the provider needs them.

## 4. Write Tests

### Unit tests

Test each method with mocked SDK calls:

```go
// internal/provider/gcp/gcp_test.go
func TestGet(t *testing.T) { /* ... */ }
func TestList(t *testing.T) { /* ... */ }
func TestSet(t *testing.T) { /* ... */ }
func TestDelete(t *testing.T) { /* ... */ }
func TestGetHistory(t *testing.T) { /* ... */ }
```

### Integration tests

Env-gated tests against the real service:

```go
// tests/integration/gcp_test.go
func TestGCPIntegration(t *testing.T) {
    if os.Getenv("SKRET_E2E_GCP") == "" {
        t.Skip("SKRET_E2E_GCP not set")
    }
    // Test against real GCP Secret Manager
}
```

Target coverage: >=95% on the provider package.

## 5. Translate Errors

Map provider-specific errors to skret's standard error codes:

```go
import "github.com/n24q02m/skret/internal/provider"

// Map GCP "NOT_FOUND" to provider.ErrNotFound
if status.Code(err) == codes.NotFound {
    return nil, provider.ErrNotFound
}
```

## 6. Document

Create `docs/providers/<name>.md` with:

- Prerequisites and setup
- IAM / permission requirements
- `.skret.yaml` configuration example
- Provider-specific quotas and limits
- Capabilities table (read, write, versioning, tagging, etc.)

## 7. Update Config Documentation

Add the new provider to `docs/reference/config-schema.md` and `docs/guide/configuration.md`.

## Checklist

- [ ] `SecretProvider` interface fully implemented
- [ ] Constructor registered in CLI and library
- [ ] Config validation for provider-specific fields
- [ ] Unit tests (>=95% coverage)
- [ ] Integration tests (env-gated)
- [ ] Error translation to standard codes
- [ ] Provider documentation page
- [ ] Config docs updated
