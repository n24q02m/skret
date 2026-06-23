package syncer

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestNewDotenv verifies that the DotenvSyncer is correctly initialized.
// This test ensures that the NewDotenv factory function correctly sets the filePath.
func TestNewDotenv(t *testing.T) {
	path := "/tmp/.env"
	s := NewDotenv(path)
	ds, ok := s.(*DotenvSyncer)
	assert.True(t, ok, "NewDotenv must return a *DotenvSyncer")
	assert.Equal(t, path, ds.filePath)
}
