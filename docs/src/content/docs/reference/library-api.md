---
title: Library API
description: "skret exposes a public Go library at `pkg/skret` for programmatic secret access."
---

skret exposes a public Go library at `pkg/skret` for programmatic secret access.

## Package Documentation

Full API reference is available on pkg.go.dev:

**[pkg.go.dev/github.com/n24q02m/skret/pkg/skret](https://pkg.go.dev/github.com/n24q02m/skret/pkg/skret)**

## Installation

```bash
go get github.com/n24q02m/skret@latest
```

## Quick Start

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/n24q02m/skret/pkg/skret"
)

func main() {
	client, err := skret.New()
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	ctx := context.Background()

	// Get a single secret
	secret, err := client.Get(ctx, "DATABASE_URL")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(secret.Value)
}
```

## API Overview

### Client Creation

```go
// Uses .skret.yaml discovery from current directory
client, err := skret.New()

// With explicit options
client, err := skret.New(skret.Options{
    WorkDir:  "/path/to/project",
    Env:      "prod",
    Provider: "aws",
    Path:     "/myapp/prod",
})
```

The `New` function discovers `.skret.yaml`, resolves configuration (applying the same precedence rules as the CLI), and initializes the provider.

### Core Methods

| Method | Description |
|--------|-------------|
| `Get(ctx, key)` | Retrieve a single secret by key |
| `List(ctx)` | List all secrets under the configured path |
| `Set(ctx, key, value, meta)` | Create or update a secret |
| `Delete(ctx, key)` | Remove a secret |
| `GetHistory(ctx, key)` | Retrieve version history for a key |
| `Rollback(ctx, key, version)` | Restore a secret to a previous version |
| `Close()` | Release provider resources |
| `Config()` | Access the resolved configuration |
| `Provider()` | Access the underlying `SecretProvider` |

### Error Handling

All methods return `*skret.Error` with a structured exit code:

```go
secret, err := client.Get(ctx, "MISSING_KEY")
if err != nil {
    code := skret.ExitCode(err)
    switch code {
    case skret.ExitNotFoundError:
        fmt.Println("Secret does not exist")
    case skret.ExitAuthError:
        fmt.Println("Authentication failed")
    default:
        fmt.Printf("Error (code %d): %v\n", code, err)
    }
}
```

## Provider Interface

For advanced use cases, you can implement the `SecretProvider` interface directly:

```go
import "github.com/n24q02m/skret/internal/provider"

type SecretProvider interface {
    Name() string
    Capabilities() Capabilities
    Get(ctx context.Context, key string) (*Secret, error)
    List(ctx context.Context, pathPrefix string) ([]*Secret, error)
    Set(ctx context.Context, key string, value string, meta SecretMeta) error
    Delete(ctx context.Context, key string) error
    GetHistory(ctx context.Context, key string) ([]*Secret, error)
    Rollback(ctx context.Context, key string, version int64) error
    Close() error
}
```

See [Adding a Provider](/contributing/adding-provider) for implementation guidance.
