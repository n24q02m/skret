package local

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/n24q02m/skret/internal/config"
	"github.com/n24q02m/skret/internal/provider"
	"gopkg.in/yaml.v3"
)

type localFile struct {
	Version string            `yaml:"version"`
	Secrets map[string]string `yaml:"secrets"`
}

// Provider reads/writes secrets from a local YAML file.
type Provider struct {
	mu       sync.Mutex
	filePath string
	data     localFile
}

// New creates a local provider from a resolved config.
func New(cfg *config.ResolvedConfig) (provider.SecretProvider, error) {
	absPath, err := filepath.Abs(cfg.File)
	if err != nil {
		return nil, fmt.Errorf("local: resolve path %q: %w", cfg.File, err)
	}

	p := &Provider{filePath: absPath}
	if err := p.load(); err != nil {
		return nil, fmt.Errorf("local: load %q: %w", absPath, err)
	}
	return p, nil
}

func (p *Provider) Name() string { return "local" }

func (p *Provider) Capabilities() provider.Capabilities {
	return provider.Capabilities{Write: true, MaxValueKB: 1024}
}

func (p *Provider) Get(_ context.Context, key string) (*provider.Secret, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	val, ok := p.data.Secrets[key]
	if !ok {
		return nil, fmt.Errorf("local: get %q: %w", key, provider.ErrNotFound)
	}
	return &provider.Secret{Key: key, Value: val}, nil
}

func (p *Provider) List(_ context.Context, _ string) ([]*provider.Secret, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	secrets := make([]*provider.Secret, 0, len(p.data.Secrets))
	for k, v := range p.data.Secrets {
		secrets = append(secrets, &provider.Secret{Key: k, Value: v})
	}
	sort.Slice(secrets, func(i, j int) bool { return secrets[i].Key < secrets[j].Key })
	return secrets, nil
}

func (p *Provider) Set(_ context.Context, key string, value string, _ provider.SecretMeta) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.data.Secrets == nil {
		p.data.Secrets = make(map[string]string)
	}
	p.data.Secrets[key] = value
	return p.save()
}

func (p *Provider) Delete(_ context.Context, key string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.data.Secrets[key]; !ok {
		return fmt.Errorf("local: delete %q: %w", key, provider.ErrNotFound)
	}
	delete(p.data.Secrets, key)
	return p.save()
}

func (p *Provider) GetHistory(_ context.Context, key string) ([]*provider.Secret, error) {
	return nil, provider.ErrCapabilityNotSupported
}

func (p *Provider) Rollback(_ context.Context, key string, version int64) error {
	return provider.ErrCapabilityNotSupported
}

func (p *Provider) Close() error { return nil }

func (p *Provider) load() error {
	raw, err := os.ReadFile(p.filePath)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(raw, &p.data)
}

func (p *Provider) save() error {
	raw, err := yaml.Marshal(&p.data)
	if err != nil {
		return fmt.Errorf("local: marshal: %w", err)
	}
	// Atomic write: temp file + rename
	dir := filepath.Dir(p.filePath)
	tmp, err := os.CreateTemp(dir, ".skret-local-*.yaml")
	if err != nil {
		return fmt.Errorf("local: create temp: %w", err)
	}
	tmpPath := tmp.Name()

	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("local: write temp: %w", err)
	}

	// Security: Set restrictive permissions on the file descriptor before closing to prevent TOCTOU
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("local: chmod temp: %w", err)
	}

	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("local: close temp: %w", err)
	}
	if err := os.Rename(tmpPath, p.filePath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("local: rename: %w", err)
	}
	return nil
}
