package cli

import (
	"strings"
	"testing"
)

// configNotFoundMsg must point the operator at the two real remedies so the
// failure is self-explanatory (Bug E fix).
func TestConfigNotFoundMessageActionable(t *testing.T) {
	for _, want := range []string{"skret init", "--path=", ".skret.yaml"} {
		if !strings.Contains(configNotFoundMsg, want) {
			t.Fatalf("configNotFoundMsg missing %q: %q", want, configNotFoundMsg)
		}
	}
}
