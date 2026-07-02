package syncer

import "fmt"

// TargetConfig is a resolved sync destination (from .skret.yaml or flags).
type TargetConfig struct {
	Type   string            // "github" | "cloudflare" | "dotenv"
	Fields map[string]string // repo / worker / pages / account / file
	Token  string            // resolved from env; never logged
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
	for _, tc := range targets {
		f, ok := registry[tc.Type]
		if !ok {
			return nil, fmt.Errorf("unknown sync target %q", tc.Type)
		}
		s, err := f(tc)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

func field(tc TargetConfig, k string) string {
	return tc.Fields[k]
}
