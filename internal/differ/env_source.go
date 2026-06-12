package differ

import (
	"context"
	"fmt"

	"github.com/n24q02m/skret/internal/exec"
	"github.com/n24q02m/skret/internal/provider"
)

type envSource struct {
	label      string
	provider   provider.SecretProvider
	pathPrefix string
}

// NewEnvSource builds a Source backed by a secret provider and path prefix.
func NewEnvSource(label string, p provider.SecretProvider, pathPrefix string) Source {
	return envSource{label: label, provider: p, pathPrefix: pathPrefix}
}

func (e envSource) Label() string { return e.label }

func (e envSource) Read(ctx context.Context) (Snapshot, error) {
	secrets, err := e.provider.List(ctx, e.pathPrefix)
	if err != nil {
		return Snapshot{}, fmt.Errorf("read %s: %w", e.label, err)
	}
	out := make(map[string]string, len(secrets))
	for _, s := range secrets {
		out[exec.KeyToEnvName(s.Key, e.pathPrefix)] = s.Value
	}
	return Snapshot{Secrets: out, CanReadValues: true}, nil
}
