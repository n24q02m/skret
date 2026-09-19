package ref

import (
	"reflect"
	"testing"
)

func scope(m map[string]string) Lookup {
	return func(name string) (string, bool) {
		v, ok := m[name]
		return v, ok
	}
}

func TestResolve_Values(t *testing.T) {
	tests := []struct {
		name  string
		value string
		scp   map[string]string
		want  string
	}{
		{"no refs passthrough", "plain-value", map[string]string{}, "plain-value"},
		{"simple ref", "${A}", map[string]string{"A": "x"}, "x"},
		{"interpolation", "postgres://${USER}:${PASS}@db:5432", map[string]string{"USER": "admin", "PASS": "p@ss"}, "postgres://admin:p@ss@db:5432"},
		{"chain", "${A}", map[string]string{"A": "${B}", "B": "${C}", "C": "leaf"}, "leaf"},
		{"repeated token", "${A}-${A}", map[string]string{"A": "x"}, "x-x"},
		{"two tokens", "${A}:${B}", map[string]string{"A": "1", "B": "2"}, "1:2"},
		{"ref to empty value", "${A}", map[string]string{"A": ""}, ""},
		{"escape backslash", `\${A}`, map[string]string{"A": "x"}, `\${A}`},
		{"escape double dollar", "$${A}", map[string]string{"A": "x"}, "$${A}"},
		{"escape embedded", `pre-\${A}-post`, map[string]string{"A": "x"}, `pre-\${A}-post`},
		{"escape embedded double", "pre-$${A}-post", map[string]string{"A": "x"}, "pre-$${A}-post"},
		{"escaped token not resolved inside chain", "${A}", map[string]string{"A": `\${B}`, "B": "x"}, `\${B}`},
		{"non-name payload kept literal", "${VAR:-default}", map[string]string{}, "${VAR:-default}"},
		{"dotted payload kept literal", "${a.b}", nil, "${a.b}"},
		{"empty payload kept literal", "${}", nil, "${}"},
		{"spaced payload kept literal", "${ A }", nil, "${ A }"},
		{"digit-leading payload kept literal", "${9A}", nil, "${9A}"},
		{"unclosed brace literal", "${unclosed", map[string]string{}, "${unclosed"},
		{"trailing close brace", "${A}}", map[string]string{"A": "x"}, "x}"},
		{"lone dollar", "a$b$c", nil, "a$b$c"},
		{"double dollar alone", "$$", nil, "$$"},
		{"bcrypt fidelity", "$2a$14$N9qo8uLOickgx2ZMRZoMye", nil, "$2a$14$N9qo8uLOickgx2ZMRZoMye"},
		{"dollar-heavy fidelity", "$$$${a}$b$c$2a$14$xyz", map[string]string{"a": "X"}, "$$$${a}$b$c$2a$14$xyz"},
		{"brace with inner dollar", "${A$B}", nil, "${A$B}"},
		{"url password dollar", "postgres://u:p$w@h/db", nil, "postgres://u:p$w@h/db"},
		{"ref resolves to value with dollar", "${A}", map[string]string{"A": "pa$$word"}, "pa$$word"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Resolve(tt.value, scope(tt.scp))
			if err != nil {
				t.Fatalf("Resolve(%q) error = %v, want nil", tt.value, err)
			}
			if got != tt.want {
				t.Fatalf("Resolve(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

func TestResolve_MissingKey(t *testing.T) {
	_, err := Resolve("pre-${NOPE}-post", scope(map[string]string{"A": "x"}))
	rerr, ok := err.(*Error)
	if !ok {
		t.Fatalf("err = %T, want *ref.Error", err)
	}
	if rerr.Kind != KindMissing || rerr.Name != "NOPE" {
		t.Fatalf("err = %+v, want KindMissing NOPE", rerr)
	}
}

func TestResolve_Cycle(t *testing.T) {
	scp := scope(map[string]string{"A": "${B}", "B": "${A}"})
	_, err := Resolve("${A}", scp)
	rerr, ok := err.(*Error)
	if !ok {
		t.Fatalf("err = %T, want *ref.Error", err)
	}
	if rerr.Kind != KindCycle {
		t.Fatalf("Kind = %v, want KindCycle", rerr.Kind)
	}
	if want := []string{"A", "B", "A"}; !reflect.DeepEqual(rerr.Chain, want) {
		t.Fatalf("Chain = %v, want %v", rerr.Chain, want)
	}
}

func TestResolve_SelfCycle(t *testing.T) {
	_, err := Resolve("${A}", scope(map[string]string{"A": "${A}"}))
	rerr, ok := err.(*Error)
	if !ok || rerr.Kind != KindCycle {
		t.Fatalf("err = %+v, want KindCycle", err)
	}
	if want := []string{"A", "A"}; !reflect.DeepEqual(rerr.Chain, want) {
		t.Fatalf("Chain = %v, want %v", rerr.Chain, want)
	}
}

func TestResolve_CycleNotTriggeredBySameKeyTwice(t *testing.T) {
	// ${A}${A} expands A once per occurrence; occurrences are siblings, not a cycle.
	got, err := Resolve("${A}${A}", scope(map[string]string{"A": "x"}))
	if err != nil {
		t.Fatalf("Resolve error = %v", err)
	}
	if got != "xx" {
		t.Fatalf("Resolve = %q, want %q", got, "xx")
	}
}

func TestResolve_DepthBound(t *testing.T) {
	// A chain of exactly MaxDepth hops resolves: K1 -> ... -> K10 (literal).
	scp := map[string]string{}
	for i := 1; i < MaxDepth; i++ {
		scp[nameOf(i)] = "${" + nameOf(i+1) + "}"
	}
	scp[nameOf(MaxDepth)] = "leaf"
	got, err := Resolve("${"+nameOf(1)+"}", scope(scp))
	if err != nil {
		t.Fatalf("chain of %d hops: error = %v, want nil", MaxDepth, err)
	}
	if got != "leaf" {
		t.Fatalf("chain of %d hops = %q, want leaf", MaxDepth, got)
	}

	// One hop deeper fails with KindDepth and the full chain.
	scp2 := map[string]string{}
	for i := 1; i <= MaxDepth; i++ {
		scp2[nameOf(i)] = "${" + nameOf(i+1) + "}"
	}
	scp2[nameOf(MaxDepth+1)] = "leaf"
	_, err = Resolve("${"+nameOf(1)+"}", scope(scp2))
	rerr, ok := err.(*Error)
	if !ok {
		t.Fatalf("err = %T, want *ref.Error", err)
	}
	if rerr.Kind != KindDepth {
		t.Fatalf("Kind = %v, want KindDepth", rerr.Kind)
	}
	if len(rerr.Chain) != MaxDepth+1 {
		t.Fatalf("Chain length = %d, want %d", len(rerr.Chain), MaxDepth+1)
	}
}

// nameOf maps 1 -> K1, 12 -> K12.
func nameOf(i int) string {
	return "K" + string(rune('0'+i/10)) + string(rune('0'+i%10))
}
