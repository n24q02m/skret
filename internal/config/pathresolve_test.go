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
		{"invalid char", `C:\Users\x\scoop\apps\git\2.54.0\myapp\dev%`, `C:\Users\x\scoop\apps\git\2.54.0\myapp\dev%`, true},
		{"only one segment", `C:\myapp`, `C:\myapp`, true},
		{"capitalized", `C:\MyApp\dev`, `C:\MyApp\dev`, true},
		{"trailing slash", `C:\myapp\dev\`, `C:\myapp\dev\`, true},
		{"no slash", `C:myapp`, `C:myapp`, true},
		{"bare path no colon", "C", "C", false},
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

func TestResolvePathAdditionalCoverage2(t *testing.T) {
	cases := []struct {
		name        string
		raw         string
		wantPath    string
		wantMangled bool
	}{
		{"bare path no colon", "C", "C", false},
		{"invalid char", `C:\Users\x\scoop\apps\git\2.54.0\myapp\dev%`, `C:\Users\x\scoop\apps\git\2.54.0\myapp\dev%`, true},
		{"only one segment", `C:\myapp`, `C:\myapp`, true},
		{"capitalized", `C:\MyApp\dev`, `C:\MyApp\dev`, true},
		{"trailing slash", `C:\myapp\dev\`, `C:\myapp\dev\`, true},
		{"empty first segment", `C:myapp/dev`, `C:myapp/dev`, true},
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

func TestResolvePathMoreCoverage3(t *testing.T) {
	cases := []struct {
		name        string
		raw         string
		wantPath    string
		wantMangled bool
	}{
		{"empty first", `C:\Users\x\scoop\apps\git\2.54.0\myapp\dev`, "/myapp/dev", true},
		{"leading slash windows", `C:\/myapp/dev`, `/myapp/dev`, true},
		{"no slash", `C:myapp`, `C:myapp`, true},
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
