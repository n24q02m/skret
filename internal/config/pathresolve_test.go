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
		{"no leading slash valid tail", "C:myapp/dev", "C:myapp/dev", true},
		{"no leading slash invalid tail", "C:Myapp/dev", "C:Myapp/dev", true},
		{"short valid segment without leading slash", "C:a/b", "C:a/b", true},
		{"multiple segments without leading slash", "C:app/prod/dev", "/prod/dev", true},
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
