//go:build !windows

package syncer

func scanStateManifestRoot(root string) ([]StateManifestFile, error) {
	return scanStateManifestRootPortable(root)
}
