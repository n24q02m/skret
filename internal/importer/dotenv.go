package importer

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
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
		line := strings.TrimSpace(scanner.Text())
		// ⚡ Bolt: Fast path prefix check avoids strings.HasPrefix overhead
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		line = strings.TrimPrefix(line, "export ")

		// ⚡ Bolt: strings.IndexByte with manual slicing is faster than strings.Cut
		idx := strings.IndexByte(line, '=')
		if idx < 0 {
			continue
		}
		key, value := line[:idx], line[idx+1:]
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		value = unquote(value)

		secrets = append(secrets, ImportedSecret{Key: key, Value: value})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("dotenv: read: %w", err)
	}
	return secrets, nil
}

func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}
