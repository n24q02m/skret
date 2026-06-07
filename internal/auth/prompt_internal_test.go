package auth

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type mockFileInfo struct {
	mode os.FileMode
}

func (m mockFileInfo) Name() string       { return "mock" }
func (m mockFileInfo) Size() int64        { return 0 }
func (m mockFileInfo) Mode() os.FileMode  { return m.mode }
func (m mockFileInfo) ModTime() time.Time { return time.Time{} }
func (m mockFileInfo) IsDir() bool        { return false }
func (m mockFileInfo) Sys() interface{}   { return nil }

func TestIsInteractiveStdin(t *testing.T) {
	tests := []struct {
		name     string
		mode     os.FileMode
		statErr  error
		expected bool
	}{
		{
			name:     "interactive terminal",
			mode:     os.ModeCharDevice,
			expected: true,
		},
		{
			name:     "non-interactive pipe",
			mode:     0,
			expected: false,
		},
		{
			name:     "stat error",
			statErr:  errors.New("stat error"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			restore := SetStdinStat(func() (os.FileInfo, error) {
				if tt.statErr != nil {
					return nil, tt.statErr
				}
				return mockFileInfo{mode: tt.mode}, nil
			})
			defer restore()

			assert.Equal(t, tt.expected, IsInteractiveStdin())
		})
	}
}
