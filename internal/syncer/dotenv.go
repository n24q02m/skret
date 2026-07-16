package syncer

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/n24q02m/skret/internal/dotenv"
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
	// The written variable name is the target-side SecretName (last path
	// segment), the same name `sync --dry-run`, github and cloudflare use, so a
	// nested provider key like "/app/prod/db/PASSWORD" becomes a valid dotenv
	// variable name ("PASSWORD") instead of the raw key. Collisions are checked
	// before opening the file so a detected clash leaves no partial output.
	type line struct{ name, value string }
	lines := make([]line, 0, len(secrets))
	nameToKey := make(map[string]string, len(secrets))
	for _, s := range secrets {
		name := SecretName(s.Key)
		// Two DISTINCT keys sharing a last segment would emit the same variable
		// name and silently lose one secret; the same key repeated is not a
		// collision. Mirrors exec.DetectEnvNameCollisions.
		if prev, ok := nameToKey[name]; ok && prev != s.Key {
			return fmt.Errorf("dotenv: variable %q is produced by two distinct keys %q and %q; rename one so secrets are not silently lost", name, prev, s.Key)
		}
		nameToKey[name] = s.Key
		lines = append(lines, line{name: name, value: s.Value})
	}
	sort.Slice(lines, func(i, j int) bool { return lines[i].name < lines[j].name })

	dir := filepath.Dir(d.filePath)
	return atomicWrite(d.filePath, dir, ".skret-sync-*.env", func(f *os.File) error {
		for _, l := range lines {
			if _, err := fmt.Fprintln(f, dotenv.Encode(l.name, l.value)); err != nil {
				return err
			}
		}
		return nil
	})
}

func init() { Register("dotenv", newDotenvFromConfig) }

func newDotenvFromConfig(tc TargetConfig) (Syncer, error) {
	file := field(tc, "file")
	if file == "" {
		file = ".env"
	}
	return NewDotenv(file), nil
}
