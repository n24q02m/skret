package syncer

import "fmt"

// TargetConfig is a resolved sync destination (from .skret.yaml or flags).
type TargetConfig struct {
	Type        string            // "github" | "cloudflare" | "dotenv"
	Fields      map[string]string // repo / worker / pages / account / file
	Token       string            // resolved from env; never logged
	NoOverwrite bool              // only write keys absent at the target
}

// Factory builds a Syncer from a resolved TargetConfig.
type Factory func(TargetConfig) (Syncer, error)

var registry = map[string]Factory{}

// Register wires a target type to its factory. Called from each target's init().
func Register(typ string, f Factory) { registry[typ] = f }

// Build constructs one Syncer per TargetConfig, erroring clearly on unknown
// types or missing required fields.
func Build(targets []TargetConfig) ([]Syncer, error) {
	out := make([]Syncer, 0, len(targets))
	for i, tc := range targets {
		f, ok := registry[tc.Type]
		if !ok {
			return nil, fmt.Errorf("sync target %d: unknown type %q", i, tc.Type)
		}
		s, err := f(tc)
		if err != nil {
			return nil, fmt.Errorf("sync target %d (%s): %w", i, tc.Type, err)
		}
		out = append(out, s)
	}
	return out, nil
}

func field(tc TargetConfig, k string) string {
	return tc.Fields[k]
}
