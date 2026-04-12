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
	defer func() { _ = f.Close() }()

	var secrets []ImportedSecret
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")

		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
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
