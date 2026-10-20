package azure

import "testing"

func TestValidateVaultName(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"valid lowercase", "my-keyvault-123", true},
		{"valid uppercase", "MyKeyVault-123", true},
		{"valid no dashes", "mykeyvault", true},
		{"valid exactly 24 chars", "a1234567890123456789012z", true},
		{"valid exactly 3 chars", "a1z", true},
		{"invalid too short", "a1", false},
		{"invalid too long", "a12345678901234567890123z", false},
		{"invalid starts with dash", "-myvault", false},
		{"invalid ends with dash", "myvault-", false},
		{"invalid chars", "my vault!", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validateVaultName(tt.in); got != tt.want {
				t.Errorf("validateVaultName(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}
