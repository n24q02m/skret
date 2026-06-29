package cli

import (
	"strings"
	"testing"
)

// configNotFoundMsg must point the operator at the two real remedies so the
// failure is self-explanatory (Bug E fix).
func TestConfigNotFoundMessageActionable(t *testing.T) {
	for _, want := range []string{"skret setup", "skret init", "--path=", ".skret.yaml", "To fix this"} {
		if !strings.Contains(configNotFoundMsg, want) {
			t.Fatalf("configNotFoundMsg missing %q: %q", want, configNotFoundMsg)
		}
	}
}

func TestFormatProviderList(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  string
	}{
		{
			name:  "empty",
			input: []string{},
			want:  "",
		},
		{
			name:  "one-aws",
			input: []string{"aws"},
			want:  "AWS SSM Parameter Store",
		},
		{
			name:  "one-unknown",
			input: []string{"gcp"},
			want:  "gcp",
		},
		{
			name:  "two",
			input: []string{"aws", "local"},
			want:  "AWS SSM Parameter Store and a local file provider",
		},
		{
			name:  "three",
			input: []string{"aws", "local", "gcp"},
			want:  "AWS SSM Parameter Store, a local file provider and gcp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatProviderList(tt.input)
			if got != tt.want {
				t.Errorf("formatProviderList() = %q, want %q", got, tt.want)
			}
		})
	}
}
