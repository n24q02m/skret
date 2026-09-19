package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/n24q02m/skret/internal/provider"
	"github.com/n24q02m/skret/internal/ref"
	"github.com/n24q02m/skret/pkg/skret"
)

// scopeLookup indexes the RAW stored values of secrets by environment name so
// ${NAME} references resolve against the same environment scope the values
// live in. Keys excluded from output/injection remain resolvable as reference
// targets: exclusion filters what leaves skret, not what is stored.
func scopeLookup(secrets []*provider.Secret, path string) ref.Lookup {
	values := make(map[string]string, len(secrets))
	for _, s := range secrets {
		values[KeyToEnvName(s.Key, path)] = s.Value
	}
	return func(name string) (string, bool) {
		v, ok := values[name]
		return v, ok
	}
}

// hasReferenceToken reports whether value plausibly contains a ${...}
// reference. Read paths use it to skip scope resolution entirely for the
// common no-reference case, keeping `get` at its previous provider cost.
func hasReferenceToken(value string) bool {
	return strings.Contains(value, "${")
}

// resolveInPlace expands references in every secret value against the scope
// formed by the secrets themselves. It mutates the slice entries in place.
func resolveInPlace(secrets []*provider.Secret, path string) error {
	lookup := scopeLookup(secrets, path)
	for _, s := range secrets {
		if !hasReferenceToken(s.Value) {
			continue
		}
		v, err := resolveValue(s.Value, KeyToEnvName(s.Key, path), lookup)
		if err != nil {
			return err
		}
		s.Value = v
	}
	return nil
}

// resolveValue expands one value against lookup, mapping ref package errors
// onto spec §7.1 exit codes with remediation hints. owner names the value's
// key in error text.
func resolveValue(value, owner string, lookup ref.Lookup) (string, error) {
	out, err := ref.Resolve(value, lookup)
	if err == nil {
		return out, nil
	}
	var rerr *ref.Error
	if !errors.As(err, &rerr) {
		return "", skret.NewError(skret.ExitValidationError, owner+": "+err.Error(), err)
	}
	switch rerr.Kind {
	case ref.KindMissing:
		return "", skret.WithRemediation(
			skret.NewError(skret.ExitValidationError,
				fmt.Sprintf("%s: reference ${%s} not found in the environment scope", owner, rerr.Name), nil),
			fmt.Sprintf("define it with 'skret set %s <value>', fix the reference, or write \\${%s} / $${%s} to keep it literal (--no-resolve reads the raw stored value)", rerr.Name, rerr.Name, rerr.Name))
	case ref.KindCycle:
		return "", skret.WithRemediation(
			skret.NewError(skret.ExitValidationError,
				fmt.Sprintf("%s: reference cycle: %s", owner, strings.Join(rerr.Chain, " -> ")), nil),
			"break the cycle: at least one key in the chain must hold a literal (non-${...}) value")
	default: // ref.KindDepth
		return "", skret.WithRemediation(
			skret.NewError(skret.ExitValidationError,
				fmt.Sprintf("%s: reference chain deeper than %d hops: %s", owner, ref.MaxDepth, strings.Join(rerr.Chain, " -> ")), nil),
			fmt.Sprintf("flatten the chain so no value sits more than %d references deep", ref.MaxDepth))
	}
}
