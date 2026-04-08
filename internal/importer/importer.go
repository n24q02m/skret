package importer

import "context"

// ImportedSecret represents a key-value pair from an external source.
type ImportedSecret struct {
	Key   string
	Value string
}

// Importer reads secrets from an external source.
type Importer interface {
	Name() string
	Import(ctx context.Context) ([]ImportedSecret, error)
}
