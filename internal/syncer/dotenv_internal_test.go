package syncer

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewDotenv(t *testing.T) {
	path := "/tmp/.env"
	s := NewDotenv(path)
	ds, ok := s.(*DotenvSyncer)
	assert.True(t, ok, "NewDotenv must return a *DotenvSyncer")
	assert.Equal(t, path, ds.filePath)
}
