//go:build !windows

package syncer

func hardenMigrationFilePermissions(_ string) error {
	return nil
}
