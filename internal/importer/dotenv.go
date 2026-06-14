package importer

import (
	"bufio"
	"context"
	"fmt"
	"os"

	"github.com/n24q02m/skret/internal/dotenv"
)

// DotenvImporter reads secrets from a dotenv file.
type DotenvImporter struct {
	filePath string
}

// NewDotenv creates a dotenv file importer.
func NewDotenv(filePath string) Importer {
	return &DotenvImporter{filePath: filePath}
}

func (d *DotenvImporter) Name() string { return "dotenv" }

func (d *DotenvImporter) Import(_ context.Context) ([]ImportedSecret, error) {
	f, err := os.Open(d.filePath)
	if err != nil {
		return nil, fmt.Errorf("dotenv: open %q: %w", d.filePath, err)
	}
	defer f.Close()

	var secrets []ImportedSecret
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		key, value, ok := dotenv.Decode(scanner.Text())
		if !ok {
			continue
		}
		secrets = append(secrets, ImportedSecret{Key: key, Value: value})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("dotenv: read: %w", err)
	}
	return secrets, nil
}
