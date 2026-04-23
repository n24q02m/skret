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

	dir := filepath.Dir(d.filePath)
	return atomicWrite(d.filePath, dir, ".skret-sync-*.env", func(f *os.File) error {
		for _, s := range secrets {
			if _, err := fmt.Fprintf(f, "%s=%q\n", s.Key, s.Value); err != nil {
				return err
			}
		}
		return nil
	})
}
