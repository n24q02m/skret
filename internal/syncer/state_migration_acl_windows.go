//go:build windows

package syncer

import (
	"fmt"

	"golang.org/x/sys/windows"
)

func hardenMigrationFilePermissions(path string) error {
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read owner security descriptor: %w", err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil {
		if err == nil {
			err = fmt.Errorf("owner SID is missing")
		}
		return fmt.Errorf("read owner SID: %w", err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.SET_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeValue: windows.TrusteeValueFromSID(owner),
			},
		},
	}, nil)
	if err != nil {
		return fmt.Errorf("build owner-only ACL: %w", err)
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	); err != nil {
		return fmt.Errorf("set owner-only ACL: %w", err)
	}
	return nil
}
