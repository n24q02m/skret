package syncer

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/n24q02m/skret/internal/provider"
)

// DotenvSyncer writes secrets to a dotenv file.
type DotenvSyncer struct {
	filePath string
}

// NewDotenv creates a dotenv file syncer.
func NewDotenv(filePath string) Syncer {
	return &DotenvSyncer{filePath: filePath}
}

func (d *DotenvSyncer) Name() string { return "dotenv" }

func (d *DotenvSyncer) Sync(_ context.Context, secrets []*provider.Secret) error {
	sort.Slice(secrets, func(i, j int) bool { return secrets[i].Key < secrets[j].Key })

	// Atomic write
	dir := filepath.Dir(d.filePath)
	tmp, err := os.CreateTemp(dir, ".skret-sync-*.env")
	if err != nil {
		return fmt.Errorf("dotenv-sync: create temp: %w", err)
	}
	tmpPath := tmp.Name()

	for _, s := range secrets {
		if _, err := fmt.Fprintf(tmp, "%s=%q\n", s.Key, s.Value); err != nil {
			tmp.Close()
			os.Remove(tmpPath)
			return fmt.Errorf("dotenv-sync: write: %w", err)
		}
	}

	// Security: Chmod on the file descriptor before closing prevents a Time-of-Check to Time-of-Use (TOCTOU) vulnerability
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("dotenv-sync: chmod: %w", err)
	}

	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("dotenv-sync: close: %w", err)
	}

	if err := os.Rename(tmpPath, d.filePath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("dotenv-sync: rename: %w", err)
	}

	return nil
}
