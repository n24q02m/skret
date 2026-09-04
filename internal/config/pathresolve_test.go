package config

import "testing"

func TestResolvePath(t *testing.T) {
	cases := []struct {
		name        string
		raw         string
		wantPath    string
		wantMangled bool
	}{
		{"empty passthrough", "", "", false},
		{"already absolute passthrough", "/myapp/dev", "/myapp/dev", false},
		{"bare relative passthrough (leading slash added later by NormalizeSSMPath)", "myapp/dev", "myapp/dev", false},
		{"msys-mangled forward-slash form recovered", "C:/Users/n24q02m-wpc/scoop/apps/git/2.54.0/myapp/dev", "/myapp/dev", true},
		{"msys-mangled backslash form recovered", `C:\Users\x\scoop\apps\git\2.54.0\myapp\dev`, "/myapp/dev", true},
		{"genuine windows path with no SSM-like tail passthrough+warn", `C:\Users\bob\Documents`, `C:\Users\bob\Documents`, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, mangled := ResolvePath(c.raw)
			if got != c.wantPath || mangled != c.wantMangled {
				t.Fatalf("ResolvePath(%q) = (%q,%v), want (%q,%v)", c.raw, got, mangled, c.wantPath, c.wantMangled)
			}
		})
	}
}

func TestIsSSMPathSegment_Coverage(t *testing.T) {
	// 73.75: character out of bounds in isSSMPathSegment
	got, _ := ResolvePath("C:/myapp/dev.prod/test")
	if got != "C:/myapp/dev.prod/test" {
		t.Errorf("Expected C:/myapp/dev.prod/test, got %v", got)
	}
}
