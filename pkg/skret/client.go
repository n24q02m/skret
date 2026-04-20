package skret

import (
	"context"
	"fmt"
	"os"

	"github.com/n24q02m/skret/internal/config"
	"github.com/n24q02m/skret/internal/provider"
	"github.com/n24q02m/skret/internal/provider/aws"
	"github.com/n24q02m/skret/internal/provider/local"
)

// Client is the main entry point for the skret programmatic API.
type Client struct {
	provider provider.SecretProvider
	config   *config.ResolvedConfig
}

// Options allows overriding default configuration discovery.
type Options struct {
	WorkDir  string
	Env      string
	Provider string
	Path     string
}

// New creates a new skret Client based on the current directory or options.
func New(opts ...Options) (*Client, error) {
	var opt Options
	if len(opts) > 0 {
		opt = opts[0]
	}

	workDir := opt.WorkDir
	if workDir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return nil, NewError(ExitConfigError, "failed to get working directory", err)
		}
		workDir = wd
	}

	cfgPath, err := config.Discover(workDir)
	if err != nil {
		return nil, NewError(ExitConfigError, "failed to discover configuration", err)
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, NewError(ExitConfigError, "failed to load configuration", err)
	}

	resolved, err := config.Resolve(cfg, config.ResolveOpts{
		Env:      opt.Env,
		Provider: opt.Provider,
		Path:     opt.Path,
	})
	if err != nil {
		return nil, NewError(ExitConfigError, "failed to resolve configuration", err)
	}

	reg := provider.NewRegistry()
	reg.Register("local", local.New)
	reg.Register("aws", aws.New)

	p, err := reg.New(resolved.Provider, resolved)
	if err != nil {
		return nil, NewError(ExitProviderError, fmt.Sprintf("failed to initialize provider %q", resolved.Provider), err)
	}

	return &Client{
		provider: p,
		config:   resolved,
	}, nil
}

// Close releases resources associated with the client.
func (c *Client) Close() error {
	return c.provider.Close()
}

// Get retrieves a single secret value by key.
func (c *Client) Get(ctx context.Context, key string) (*provider.Secret, error) {
	s, err := c.provider.Get(ctx, key)
	if err != nil {
		return nil, NewError(ExitNotFoundError, fmt.Sprintf("failed to get secret %q", key), err)
	}
	return s, nil
}

// List retrieves all secrets under the defined environment path.
func (c *Client) List(ctx context.Context) ([]*provider.Secret, error) {
	secrets, err := c.provider.List(ctx, c.config.Path)
	if err != nil {
		return nil, NewError(ExitProviderError, "failed to list secrets", err)
	}
	return secrets, nil
}

// Set creates or updates a secret.
func (c *Client) Set(ctx context.Context, key, value string, meta provider.SecretMeta) error {
	err := c.provider.Set(ctx, key, value, meta)
	if err != nil {
		return NewError(ExitProviderError, fmt.Sprintf("failed to set secret %q", key), err)
	}
	return nil
}

// Delete removes a secret.
func (c *Client) Delete(ctx context.Context, key string) error {
	err := c.provider.Delete(ctx, key)
	if err != nil {
		return NewError(ExitProviderError, fmt.Sprintf("failed to delete secret %q", key), err)
	}
	return nil
}

// GetHistory retrieves the version history of a secret.
func (c *Client) GetHistory(ctx context.Context, key string) ([]*provider.Secret, error) {
	history, err := c.provider.GetHistory(ctx, key)
	if err != nil {
		return nil, NewError(ExitProviderError, fmt.Sprintf("failed to get history for secret %q", key), err)
	}
	return history, nil
}

// Rollback restores a secret to a specific previous version.
func (c *Client) Rollback(ctx context.Context, key string, version int64) error {
	err := c.provider.Rollback(ctx, key, version)
	if err != nil {
		return NewError(ExitProviderError, fmt.Sprintf("failed to rollback secret %q to version %d", key, version), err)
	}
	return nil
}

// Config returns the resolved configuration for the client.
func (c *Client) Config() *config.ResolvedConfig {
	return c.config
}

// Provider returns the underlying secret provider.
func (c *Client) Provider() provider.SecretProvider {
	return c.provider
}
