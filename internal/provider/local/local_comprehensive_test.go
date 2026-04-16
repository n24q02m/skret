package local_test

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/n24q02m/skret/internal/config"
	"github.com/n24q02m/skret/internal/provider"
	"github.com/n24q02m/skret/internal/provider/local"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Malformed YAML ---

func TestLocal_MalformedYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	err := os.WriteFile(path, []byte(`{{{not valid yaml`), 0o600)
	require.NoError(t, err)

	_, err = local.New(&config.ResolvedConfig{File: path})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "local: load")
}

// --- Empty secrets file ---

func TestLocal_EmptyFile(t *testing.T) {
	path := setupFile(t, "version: \"1\"\n")
	p := newProvider(t, path)
	defer func() { _ = p.Close() }()

	secrets, err := p.List(context.Background(), "")
	require.NoError(t, err)
	assert.Empty(t, secrets)
}

// --- Get/Set/Delete flow ---

func TestLocal_FullLifecycle(t *testing.T) {
	path := setupFile(t, "version: \"1\"\nsecrets:\n  INITIAL: val")
	p := newProvider(t, path)
	defer func() { _ = p.Close() }()

	ctx := context.Background()

	// Get existing
	s, err := p.Get(ctx, "INITIAL")
	require.NoError(t, err)
	assert.Equal(t, "val", s.Value)

	// Set new
	err = p.Set(ctx, "NEW_KEY", "new_val", provider.SecretMeta{})
	require.NoError(t, err)

	// Get new
	s, err = p.Get(ctx, "NEW_KEY")
	require.NoError(t, err)
	assert.Equal(t, "new_val", s.Value)

	// Update existing
	err = p.Set(ctx, "NEW_KEY", "updated_val", provider.SecretMeta{})
	require.NoError(t, err)
	s, err = p.Get(ctx, "NEW_KEY")
	require.NoError(t, err)
	assert.Equal(t, "updated_val", s.Value)

	// Delete
	err = p.Delete(ctx, "NEW_KEY")
	require.NoError(t, err)

	// Verify deleted
	_, err = p.Get(ctx, "NEW_KEY")
	assert.ErrorIs(t, err, provider.ErrNotFound)

	// Original still exists
	s, err = p.Get(ctx, "INITIAL")
	require.NoError(t, err)
	assert.Equal(t, "val", s.Value)
}

// --- Concurrent read/write contention ---

func TestLocal_ConcurrentMixed(t *testing.T) {
	path := setupFile(t, "version: \"1\"\nsecrets:\n  KEY: initial")
	p := newProvider(t, path)
	defer func() { _ = p.Close() }()

	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make(chan error, 20)

	// 5 concurrent writers
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(_ int) {
			defer wg.Done()
			if err := p.Set(ctx, "KEY", "value", provider.SecretMeta{}); err != nil {
				errs <- err
			}
		}(i)
	}

	// 5 concurrent readers
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := p.List(ctx, ""); err != nil {
				errs <- err
			}
		}()
	}

	// 5 concurrent gets
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = p.Get(ctx, "KEY") // might not found during concurrent delete, ok
		}()
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		require.NoError(t, err)
	}
}

// --- Atomic rename verification ---

func TestLocal_AtomicWriteVerification(t *testing.T) {
	path := setupFile(t, "version: \"1\"\nsecrets:\n  KEY1: val1")
	p := newProvider(t, path)
	defer func() { _ = p.Close() }()

	ctx := context.Background()

	// Write many keys to trigger atomic save multiple times
	for i := 0; i < 10; i++ {
		key := "ATOMIC_KEY_" + string(rune('A'+i))
		err := p.Set(ctx, key, "value", provider.SecretMeta{})
		require.NoError(t, err)
	}

	// Verify all were written by creating a fresh provider from the same file
	p2 := newProvider(t, path)
	defer func() { _ = p2.Close() }()

	secrets, err := p2.List(ctx, "")
	require.NoError(t, err)
	// 1 original + 10 new keys
	assert.Len(t, secrets, 11)
}

// --- GetHistory not supported ---

func TestLocal_GetHistory_NotSupported(t *testing.T) {
	path := setupFile(t, "version: \"1\"\nsecrets:\n  KEY: val")
	p := newProvider(t, path)
	defer func() { _ = p.Close() }()

	_, err := p.GetHistory(context.Background(), "KEY")
	assert.ErrorIs(t, err, provider.ErrCapabilityNotSupported)
}

// --- Rollback not supported ---

func TestLocal_Rollback_NotSupported(t *testing.T) {
	path := setupFile(t, "version: \"1\"\nsecrets:\n  KEY: val")
	p := newProvider(t, path)
	defer func() { _ = p.Close() }()

	err := p.Rollback(context.Background(), "KEY", 1)
	assert.ErrorIs(t, err, provider.ErrCapabilityNotSupported)
}

// --- Close idempotent ---

func TestLocal_Close_Idempotent(t *testing.T) {
	path := setupFile(t, "version: \"1\"\nsecrets:\n  KEY: val")
	p := newProvider(t, path)

	err := p.Close()
	assert.NoError(t, err)
	err = p.Close()
	assert.NoError(t, err)
}

// --- Capabilities check ---

func TestLocal_Capabilities_Complete(t *testing.T) {
	path := setupFile(t, "version: \"1\"\nsecrets:\n  KEY: val")
	p := newProvider(t, path)
	defer func() { _ = p.Close() }()

	caps := p.Capabilities()
	assert.True(t, caps.Write)
	assert.False(t, caps.Versioning)
	assert.False(t, caps.Tagging)
	assert.False(t, caps.Rotation)
	assert.False(t, caps.AuditLog)
	assert.Equal(t, 1024, caps.MaxValueKB)
}

// --- Special characters in values ---

func TestLocal_SpecialCharValues(t *testing.T) {
	path := setupFile(t, "version: \"1\"\nsecrets:\n  KEY: val")
	p := newProvider(t, path)
	defer func() { _ = p.Close() }()

	ctx := context.Background()

	tests := []struct {
		key   string
		value string
	}{
		{"QUOTES", `value with "double" quotes`},
		{"NEWLINES", "line1\nline2\nline3"},
		{"UNICODE", "emoji and unicode: test value"},
		{"EQUALS", "key=value=extra"},
		{"EMPTY", ""},
		{"SPACES", "  leading and trailing  "},
		{"BACKSLASH", `path\to\file`},
	}

	for _, tt := range tests {
		err := p.Set(ctx, tt.key, tt.value, provider.SecretMeta{})
		require.NoError(t, err, "Set %q failed", tt.key)

		s, err := p.Get(ctx, tt.key)
		require.NoError(t, err, "Get %q failed", tt.key)
		assert.Equal(t, tt.value, s.Value, "Value mismatch for %q", tt.key)
	}

	// Verify persistence by creating a new provider
	p2 := newProvider(t, path)
	defer func() { _ = p2.Close() }()

	for _, tt := range tests {
		s, err := p2.Get(ctx, tt.key)
		require.NoError(t, err, "Persisted Get %q failed", tt.key)
		assert.Equal(t, tt.value, s.Value, "Persisted value mismatch for %q", tt.key)
	}
}
