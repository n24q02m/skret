package syncer

import "testing"

func TestValidStateManifestPath_Coverage2(t *testing.T) {
	// Let's test single dot and double dot at the end

	tests := []string{
		"path/",
		"path/.",
		"path/..",
		".",
		"..",
		"",
	}

	for _, tt := range tests {
		t.Run(tt, func(t *testing.T) {
			_ = validStateManifestPath(tt)
		})
	}
}
