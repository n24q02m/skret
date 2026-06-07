package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsNonInteractive(t *testing.T) {
	orig := isInteractiveStdin
	defer func() { isInteractiveStdin = orig }()

	tests := []struct {
		name           string
		envVal         string
		interactive    bool
		wantNonInter   bool
	}{
		{
			name:         "SKRET_NON_INTERACTIVE=1 forces non-interactive",
			envVal:       "1",
			interactive:  true,
			wantNonInter: true,
		},
		{
			name:         "SKRET_NON_INTERACTIVE=1 forces non-interactive (even if non-interactive stdin)",
			envVal:       "1",
			interactive:  false,
			wantNonInter: true,
		},
		{
			name:         "interactive stdin and no env var",
			envVal:       "",
			interactive:  true,
			wantNonInter: false,
		},
		{
			name:         "non-interactive stdin and no env var",
			envVal:       "",
			interactive:  false,
			wantNonInter: true,
		},
		{
			name:         "SKRET_NON_INTERACTIVE=0 (or any other value) is ignored, follows stdin",
			envVal:       "0",
			interactive:  true,
			wantNonInter: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("SKRET_NON_INTERACTIVE", tt.envVal)
			isInteractiveStdin = func() bool { return tt.interactive }
			assert.Equal(t, tt.wantNonInter, isNonInteractive())
		})
	}
}
