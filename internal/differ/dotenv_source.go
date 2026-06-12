package differ

import (
	"context"
	"fmt"

	"github.com/n24q02m/skret/internal/exec"
	"github.com/n24q02m/skret/internal/importer"
)

type dotenvSource struct {
	filePath string
}

// NewDotenvSource builds a Source backed by a dotenv file.
func NewDotenvSource(filePath string) Source {
	return dotenvSource{filePath: filePath}
}

func (d dotenvSource) Label() string { return "file:" + d.filePath }

func (d dotenvSource) Read(ctx context.Context) (Snapshot, error) {
	imported, err := importer.NewDotenv(d.filePath).Import(ctx)
	if err != nil {
		return Snapshot{}, fmt.Errorf("read %s: %w", d.Label(), err)
	}
	out := make(map[string]string, len(imported))
	for _, s := range imported {
		out[exec.KeyToEnvName(s.Key, "")] = s.Value
	}
	return Snapshot{Secrets: out, CanReadValues: true}, nil
}
